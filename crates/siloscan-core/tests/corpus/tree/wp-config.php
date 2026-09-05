<?php
// WordPress configuration for the storefront plugin, Freemius SDK wired in.

define('DB_NAME', 'storefront');
define('DB_USER', 'wp_app');
define('DB_PASSWORD', getenv('WORDPRESS_DB_PASSWORD'));

$freemius = fs_dynamic_init(array(
    'id'         => '4821',
    'slug'       => 'storefront-plugin',
    'public_key' => 'pk_a1b2c3d4e5f60718293a4b5c6',
    'secret_key' => '{{FREEMIUS_29_921}}',
    'is_premium' => true,
));

$freemius_staging = array(
    'secret_key' => getenv('FS_STAGING_SECRET_KEY'),
    'plan'       => 'storefront-pro-annual',
);
