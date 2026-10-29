<?php

namespace Pikoman\Compat;

use InvalidArgumentException;
use RuntimeException;
use SensitiveParameter;

/**
 * Publishes to Pikoman and signs join tokens, with the app's Ed25519 keys. No shared secret: the
 * API key signs a token for each request, and the private key signs join tokens. The keys are
 * marked sensitive, so a stack trace never shows them, and `var_dump` shows them hidden.
 */
class Client
{
    /** Full member: reads and sends client events. A join token's `access`. */
    private const MEMBER_ACCESS = 3;

    /** Seconds a join token is good for; Pikoman accepts at most 600. */
    private const TOKEN_LIFETIME = 300;

    /** A request token is made for one request and lives a minute. */
    private const REQUEST_LIFETIME = 60;

    /** PKCS#8 DER of an Ed25519 private key, before its 32-byte seed. */
    private const PKCS8_PREFIX = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20";

    private const ENCRYPTED_PREFIX = 'private-encrypted-';

    /** Plain http is only for a server on this machine, as in @pikoman/ws. */
    private const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

    private const JSON = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

    private string $apiKeyId;

    private string $apiSecretKey;

    private string $signingSecretKey;

    /** As given; read on first use, so a bad key breaks only encrypted channels. */
    private ?string $encryptionKey;

    private ?string $masterKey = null;

    /**
     * `$encryptionKey` is the master key for `private-encrypted-` channels: 32 random bytes,
     * base64, kept by this backend and never sent to Pikoman.
     */
    public function __construct(
        private string $app,
        #[SensitiveParameter] string $apiKey,
        #[SensitiveParameter] string $privateKey,
        private string $address = 'https://next-api.pikoman.se',
        private ?string $signingKeyId = null,
        #[SensitiveParameter] ?string $encryptionKey = null,
    ) {
        if (! preg_match('/\Ask_(k_[0-9a-f]{16})\.([A-Za-z0-9_-]{43})\z/', trim($apiKey), $match)) {
            throw new InvalidArgumentException('PIKOMAN_API_KEY is not a Pikoman API key (sk_k_<16 hex>.<43 characters>)');
        }
        $this->apiKeyId = $match[1];
        $this->apiSecretKey = self::secretKey(self::base64UrlDecode($match[2]));
        $this->signingSecretKey = self::secretKey(self::seedOf($privateKey));
        $this->address = self::checkedAddress($address);
        $this->encryptionKey = $encryptionKey === null || trim($encryptionKey) === '' ? null : trim($encryptionKey);
    }

    /**
     * Publishes `$event` with `$data` to the channels in one request (`POST /mass_events`), which
     * reaches all of them or none.
     */
    public function trigger(array $channels, string $event, mixed $data): void
    {
        $this->publish([['channels' => $channels, 'event' => $event, 'data' => $data]]);
    }

    /**
     * Publishes several events, each `['channels' => [...], 'event' => ..., 'data' => ...]`, in
     * one request that reaches all of them or none. The plain channels of an event share one
     * entry; each encrypted channel gets its own, since its data is encrypted with its own key.
     */
    public function publish(array $events): void
    {
        $entries = [];
        foreach ($events as ['channels' => $channels, 'event' => $event, 'data' => $data]) {
            if ($event === '' || str_starts_with($event, 'client-')) {
                throw new InvalidArgumentException("Pikoman: {$event} is not an event a backend may publish");
            }
            $plain = array_values(array_filter($channels, fn ($channel) => ! str_starts_with($channel, self::ENCRYPTED_PREFIX)));
            if ($plain !== []) {
                $entries[] = ['channels' => $plain, 'event' => $event, 'data' => $data];
            }
            foreach ($channels as $channel) {
                if (str_starts_with($channel, self::ENCRYPTED_PREFIX)) {
                    $entries[] = ['channels' => [$channel], 'event' => $event, 'data' => $this->encrypt($channel, $event, $data)];
                }
            }
        }
        if ($entries !== []) {
            $this->post('/mass_events', json_encode($entries, self::JSON));
        }
    }

    /**
     * Lets a connection into a private or presence channel: `['auth' => <join token>]`, which
     * @pikoman/compat in the browser joins with, and for a `private-encrypted-` channel the channel
     * key as `shared_secret`, as Pusher's does. For presence, the member's user id and info.
     */
    public function authorizeChannel(string $socketId, string $channel, ?array $presence = null): array
    {
        if (! preg_match('/\Ac_[A-Za-z0-9]{1,64}\z/', $socketId)) {
            throw new InvalidArgumentException('Not a Pikoman connection id');
        }
        if (! str_starts_with($channel, 'private-') && ! str_starts_with($channel, 'presence-')) {
            throw new InvalidArgumentException("Pikoman: {$channel} is not a private or presence channel");
        }
        $token = $this->sign([
            'connection' => $socketId,
            'channel' => $channel,
            'access' => self::MEMBER_ACCESS,
            'data' => $presence,
            'exp' => time() + self::TOKEN_LIFETIME,
        ], $this->signingSecretKey, $this->signingKeyId);

        if (str_starts_with($channel, self::ENCRYPTED_PREFIX)) {
            return ['auth' => $token, 'shared_secret' => base64_encode($this->channelKey($channel))];
        }

        return $presence === null
            ? ['auth' => $token]
            : ['auth' => $token, 'channel_data' => json_encode($presence, self::JSON)];
    }

    /** What `var_dump` and `print_r` show: never a key. */
    public function __debugInfo(): array
    {
        return ['app' => $this->app, 'address' => $this->address, 'keys' => '[hidden]'];
    }

    /**
     * An event for a `private-encrypted-` channel, as @pikoman/ws reads it: AES-256-GCM with the
     * channel key, a fresh 12-byte nonce, the tag after the ciphertext, and
     * "server\n<channel>\n<event>" as additional data.
     */
    private function encrypt(string $channel, string $event, mixed $data): array
    {
        $nonce = random_bytes(12);
        $ciphertext = openssl_encrypt(
            json_encode($data, self::JSON),
            'aes-256-gcm',
            $this->channelKey($channel),
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            "server\n{$channel}\n{$event}",
        );
        if ($ciphertext === false) {
            throw new RuntimeException('Pikoman: could not encrypt the event');
        }

        return ['nonce' => base64_encode($nonce), 'ciphertext' => base64_encode($ciphertext.$tag)];
    }

    /** HMAC-SHA256(master key, "<app>\n<channel>"): the key members of the channel get. */
    private function channelKey(string $channel): string
    {
        if ($this->masterKey === null) {
            if ($this->encryptionKey === null) {
                throw new RuntimeException('Pikoman: an encrypted channel needs PIKOMAN_ENCRYPTION_KEY');
            }
            // Standard base64 with padding, the only form @pikoman/ws reads.
            if (! preg_match('/\A[A-Za-z0-9+\/]{43}=\z/', $this->encryptionKey)) {
                throw new RuntimeException('Pikoman: PIKOMAN_ENCRYPTION_KEY is 32 bytes in base64 (44 characters, ending in =)');
            }
            $this->masterKey = base64_decode($this->encryptionKey, true);
        }

        return hash_hmac('sha256', "{$this->app}\n{$channel}", $this->masterKey, true);
    }

    private function post(string $path, string $body): void
    {
        $iat = time();
        $token = $this->sign([
            'iss' => $this->app,
            'iat' => $iat,
            'exp' => $iat + self::REQUEST_LIFETIME,
            'htm' => 'POST',
            'htu' => $path,
            'bh' => self::base64UrlEncode(hash('sha256', $body, true)),
        ], $this->apiSecretKey, $this->apiKeyId);

        // No curl_close(): a handle is freed when it goes out of scope, and the call is deprecated.
        $curl = curl_init($this->address.$path);
        curl_setopt_array($curl, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => ['Authorization: Bearer '.$token, 'Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
        ]);
        $answer = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        if ($answer === false) {
            throw new RuntimeException('Pikoman: publish failed: '.curl_error($curl));
        }
        if ($status < 200 || $status >= 300) {
            throw new RuntimeException("Pikoman: publish failed: {$status} {$answer}");
        }
    }

    private function sign(array $payload, #[SensitiveParameter] string $secretKey, ?string $keyId): string
    {
        $header = ['alg' => 'EdDSA', 'typ' => 'JWT'];
        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }
        $signed = self::base64UrlEncode(json_encode($header, self::JSON)).'.'.self::base64UrlEncode(json_encode($payload, self::JSON));

        return $signed.'.'.self::base64UrlEncode(sodium_crypto_sign_detached($signed, $secretKey));
    }

    private static function checkedAddress(string $address): string
    {
        $trimmed = rtrim(trim($address), '/');
        $scheme = parse_url($trimmed, PHP_URL_SCHEME);
        $host = parse_url($trimmed, PHP_URL_HOST);
        if ($scheme === 'https' || ($scheme === 'http' && in_array($host, self::LOCAL_HOSTS, true))) {
            return $trimmed;
        }
        throw new InvalidArgumentException("Pikoman: {$trimmed}: use https:// (plain http:// only for localhost)");
    }

    /** The 32-byte seed of the dashboard's private key: one line of base64 PKCS#8, or a PEM. */
    private static function seedOf(#[SensitiveParameter] string $privateKey): string
    {
        $base64 = preg_replace('/-----(BEGIN|END) PRIVATE KEY-----|\s+/', '', $privateKey);
        $der = base64_decode($base64, true);
        if ($der === false || strlen($der) !== 48 || ! str_starts_with($der, self::PKCS8_PREFIX)) {
            throw new InvalidArgumentException('PIKOMAN_PRIVATE_KEY is not an Ed25519 private key (PKCS#8)');
        }

        return substr($der, 16);
    }

    private static function secretKey(#[SensitiveParameter] string $seed): string
    {
        if (strlen($seed) !== 32) {
            throw new InvalidArgumentException('An Ed25519 seed is 32 bytes');
        }

        return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
    }

    private static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(#[SensitiveParameter] string $text): string
    {
        return base64_decode(strtr($text, '-_', '+/'));
    }
}
