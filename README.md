# pikoman/compat-php

Move a PHP backend from Pusher's library (`pusher/pusher-php-server`) to
[Pikoman](https://pikoman.se) by changing the `use` line and your keys. `trigger`,
`triggerBatch`, `authorizeChannel` and `authorizePresenceChannel` take the same arguments and
give the same answers, so the code that calls them, your auth endpoint included, stays as it is.
PHP 8.2 or later with the curl, openssl and sodium extensions. For Laravel, use
[`pikoman/compat-laravel`](https://packagist.org/packages/pikoman/compat-laravel), which is built
on this.

```bash
composer require pikoman/compat-php
```

```php
use Pikoman\Compat\Pusher;   // was: use Pusher\Pusher;

$pusher = new Pusher(
    getenv('PIKOMAN_APP'),          // was: the key
    getenv('PIKOMAN_API_KEY'),      // was: the secret
    getenv('PIKOMAN_PRIVATE_KEY'),  // was: the app id
);
```

The three keys are in Pikoman's dashboard; left out, they are read from `PIKOMAN_APP`,
`PIKOMAN_API_KEY` and `PIKOMAN_PRIVATE_KEY`. Nothing is signed with a shared secret: the API key
signs each request and the private key signs join tokens, and Pikoman only holds the public halves.
Pusher's options `cluster`, `useTLS`, `host`, `port`, `scheme` and `timeout` are ignored, so
yours can stay.

Unchanged:

```php
$pusher->trigger('orders', 'order-shipped', ['id' => 1042]);
$pusher->trigger(['orders', 'admin'], 'order-shipped', $data, ['socket_id' => $_POST['socket_id']]);
$pusher->triggerBatch([
    ['channel' => 'orders', 'name' => 'order-shipped', 'data' => ['id' => 1042]],
    ['channel' => 'stock', 'name' => 'changed', 'data' => ['sku' => 'A7']],
]);

// The auth endpoint
echo $pusher->authorizeChannel($_POST['channel_name'], $_POST['socket_id']);
echo $pusher->authorizePresenceChannel($_POST['channel_name'], $_POST['socket_id'], $userId, ['name' => $name]);
```

In the browser, `import Pusher from "@pikoman/compat"` in place of `pusher-js`
([npm](https://www.npmjs.com/package/@pikoman/compat)).

## What it covers

- `trigger` to one channel or up to 100, and `triggerBatch`, each in one request that reaches all
  of its channels or none. Data is encoded as Pusher's library encodes it: text arrives as text
  unless you pass `$already_encoded = true`.
- `socket_id` (keep an event from the sender's page) for data that is an object.
- Private, presence and `private-encrypted-` channels. For encrypted channels, pass
  `['encryption_master_key_base64' => ...]` as the fourth argument, as with Pusher, or set
  `PIKOMAN_ENCRYPTION_KEY`: 32 random bytes, base64, kept by your backend and never sent to Pikoman.
- `socketAuth`, `socket_auth`, `presenceAuth` and `presence_auth`, the names of older versions.

Not yet: `get`, `getChannelInfo`, `getChannels`, `getPresenceUsers`, `sendToUser`,
`authenticateUser`, `terminateUserConnections`, the `Async` methods and `webhook` (Pikoman's
webhooks have their own format). Write to hello@pikoman.se if you need one of them.

Step by step for each kind of app: [pikoman.se/switch-from-pusher](https://pikoman.se/switch-from-pusher/).
Source: [github.com/pikomanse/compat-php](https://github.com/pikomanse/compat-php).

MIT licensed.
