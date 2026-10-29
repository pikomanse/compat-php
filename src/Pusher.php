<?php

namespace Pikoman\Compat;

use InvalidArgumentException;
use JsonException;
use SensitiveParameter;
use stdClass;

/**
 * The parts of Pusher's PHP library (`pusher/pusher-php-server`) that backends use, on Pikoman:
 * the same method names, arguments and return values, so moving is the `use` line and the keys.
 *
 *   use Pikoman\Compat\Pusher;
 *   $pusher = new Pusher(getenv('PIKOMAN_APP'), getenv('PIKOMAN_API_KEY'), getenv('PIKOMAN_PRIVATE_KEY'));
 *   $pusher->trigger('orders', 'order-shipped', ['id' => 1042]);
 *   echo $pusher->authorizeChannel($_POST['channel_name'], $_POST['socket_id']);
 *
 * Where Pusher takes a key, a secret and an app id, this takes the app, the API key and the
 * private key from Pikoman's dashboard. Nothing is signed with a shared secret: the API key signs
 * each request and the private key signs join tokens.
 */
class Pusher
{
    /** Pusher's limit per trigger, kept so code that works there works here. */
    private const MAX_CHANNELS = 100;

    /** Connection ids as the server makes them. */
    private const CONNECTION_ID = '/\Ac_[A-Za-z0-9]{1,64}\z/';

    /** The field @pikoman/compat in the browser reads: the connection that should not get the event. */
    private const SKIP = '__pikoman_skip';

    private Client $client;

    /**
     * `$app`, `$apiKey` and `$privateKey` default to `PIKOMAN_APP`, `PIKOMAN_API_KEY` and
     * `PIKOMAN_PRIVATE_KEY`. Options: `encryption_master_key_base64` as in Pusher's library (or
     * `PIKOMAN_ENCRYPTION_KEY`: 32 random bytes, base64, kept by your backend and never sent to
     * Pikoman), `address` for another Pikoman API, `signing_key_id`. Pusher's `cluster`,
     * `useTLS`, `host`, `port`, `scheme` and `timeout` are ignored, so the options of existing
     * code can stay.
     */
    public function __construct(
        ?string $app = null,
        #[SensitiveParameter] ?string $apiKey = null,
        #[SensitiveParameter] ?string $privateKey = null,
        #[SensitiveParameter] array $options = [],
    ) {
        $app = self::orEnv($app, 'PIKOMAN_APP');
        $apiKey = self::orEnv($apiKey, 'PIKOMAN_API_KEY');
        $privateKey = self::orEnv($privateKey, 'PIKOMAN_PRIVATE_KEY');
        if ($app === null || $apiKey === null || $privateKey === null) {
            throw new InvalidArgumentException('Pikoman: needs the app, the API key and the private key (or PIKOMAN_APP, PIKOMAN_API_KEY, PIKOMAN_PRIVATE_KEY)');
        }
        $this->client = new Client(
            $app,
            $apiKey,
            $privateKey,
            $options['address'] ?? 'https://next-api.pikoman.se',
            $options['signing_key_id'] ?? null,
            self::orEnv($options['encryption_master_key_base64'] ?? null, 'PIKOMAN_ENCRYPTION_KEY'),
        );
    }

    /**
     * Publishes `$event` to one channel or up to 100, in one request that reaches all of them or
     * none. `$data` is encoded as JSON, so text arrives as text, unless `$already_encoded` says it
     * is JSON already; as with Pusher. With `['socket_id' => ...]` in `$params`, that connection's
     * page does not get the event; this works for data that is an object. Returns an empty
     * object, as Pusher does without `info`.
     */
    public function trigger($channels, string $event, $data, array $params = [], bool $already_encoded = false): object
    {
        $channels = is_array($channels) ? array_values($channels) : [$channels];
        if (count($channels) > self::MAX_CHANNELS) {
            throw new InvalidArgumentException('Pikoman: at most '.self::MAX_CHANNELS.' channels per trigger');
        }
        $this->client->trigger($channels, $event, self::withSkip(self::encoded($data, $already_encoded), $params['socket_id'] ?? null));

        return (object) [];
    }

    /**
     * `[['channel' => ..., 'name' => ..., 'data' => ..., 'socket_id' => ...]]`, as with Pusher,
     * in one request that reaches all of them or none.
     */
    public function triggerBatch(array $batch = [], bool $already_encoded = false): object
    {
        $events = [];
        foreach ($batch as $event) {
            $events[] = [
                'channels' => [$event['channel']],
                'event' => $event['name'],
                'data' => self::withSkip(self::encoded($event['data'] ?? null, $already_encoded), $event['socket_id'] ?? null),
            ];
        }
        $this->client->publish($events);

        return (object) [];
    }

    /**
     * Lets a connection into a private or presence channel, as JSON for the browser:
     * `{"auth": <join token>}`, and for a `private-encrypted-` channel the channel key as
     * `shared_secret`. `$custom_data` is the presence member as JSON, `{"user_id", "user_info"}`.
     */
    public function authorizeChannel(string $channel, string $socket_id, ?string $custom_data = null): string
    {
        $presence = null;
        if (str_starts_with($channel, 'presence-')) {
            $member = $custom_data === null ? null : json_decode($custom_data, true);
            if (! is_array($member) || ! isset($member['user_id'])) {
                throw new InvalidArgumentException('Pikoman: a presence channel needs the member with a user_id');
            }
            $presence = ['user_id' => (string) $member['user_id'], 'user_info' => $member['user_info'] ?? null];
        }

        return json_encode(
            $this->client->authorizeChannel($socket_id, $channel, $presence),
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        );
    }

    /** The member of a presence channel, as with Pusher. */
    public function authorizePresenceChannel(string $channel, string $socket_id, string $user_id, $user_info = null): string
    {
        $member = ['user_id' => $user_id];
        if ($user_info) {
            $member['user_info'] = $user_info;
        }

        return $this->authorizeChannel($channel, $socket_id, json_encode($member, JSON_THROW_ON_ERROR));
    }

    /** The name older versions of Pusher's library used. */
    public function socketAuth(string $channel, string $socket_id, ?string $custom_data = null): string
    {
        return $this->authorizeChannel($channel, $socket_id, $custom_data);
    }

    /** The name older versions of Pusher's library used. */
    public function socket_auth(string $channel, string $socket_id, ?string $custom_data = null): string
    {
        return $this->authorizeChannel($channel, $socket_id, $custom_data);
    }

    /** The name older versions of Pusher's library used. */
    public function presenceAuth(string $channel, string $socket_id, string $user_id, $user_info = null): string
    {
        return $this->authorizePresenceChannel($channel, $socket_id, $user_id, $user_info);
    }

    /** The name older versions of Pusher's library used. */
    public function presence_auth(string $channel, string $socket_id, string $user_id, $user_info = null): string
    {
        return $this->authorizePresenceChannel($channel, $socket_id, $user_id, $user_info);
    }

    /** What `var_dump` and `print_r` show: never a key. */
    public function __debugInfo(): array
    {
        return $this->client->__debugInfo();
    }

    /**
     * The event's data as Pusher sends it: JSON text, which the browser parses once. Text that is
     * not `$already_encoded` is encoded too, so it arrives as the same text.
     */
    private static function encoded(mixed $data, bool $alreadyEncoded): string
    {
        if ($alreadyEncoded && is_string($data)) {
            return $data;
        }

        return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * The data with the connection that should not get it, which @pikoman/compat in the browser
     * reads. Only an object can carry it; other data goes to everyone.
     */
    private static function withSkip(string $encoded, mixed $socketId): string
    {
        if ($socketId === null) {
            return $encoded;
        }
        if (! is_string($socketId) || ! preg_match(self::CONNECTION_ID, $socketId)) {
            throw new InvalidArgumentException('Pikoman: socket_id is not a Pikoman connection id');
        }
        try {
            $value = json_decode($encoded, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $encoded;
        }
        if (! $value instanceof stdClass) {
            return $encoded;
        }
        $value->{self::SKIP} = $socketId;

        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    private static function orEnv(?string $value, string $name): ?string
    {
        if ($value !== null && trim($value) !== '') {
            return $value;
        }
        $env = $_ENV[$name] ?? $_SERVER[$name] ?? getenv($name);

        return is_string($env) && trim($env) !== '' ? $env : null;
    }
}
