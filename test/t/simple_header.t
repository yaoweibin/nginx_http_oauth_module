#
#===============================================================================
#
#  DESCRIPTION: test 
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Weibin Yao (http://yaoweibin.cn/), yaoweibin@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  03/02/2010 03:18:28 PM
#     REVISION:  ---
#===============================================================================


# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the simple_get test
--- config
resolver 192.168.203.2;
server {
    listen       1982;
    server_name  localhost;

    oauth_consumer_key key;
    oauth_consumer_secret secret;
    oauth_realm "http://example.org";
    oauth_variables $oauth_token $oauth_token_secret $proxy_uri;
    session_zone $user_id zone=test:10m;

#two step oauth
    location  /{
        set $user_id yaoweibin;

        if ($user_id = "") {
            rewrite (.*) /session last;
        }

        rewrite (.*) /get_local_session last;

        return 404;
    }

    location /get_local_session {
        session_get zone=test $oauth_token $oauth_token_secret;

        if ($oauth_token = "") {
            rewrite (.*) /session last;
        }

        if ($oauth_token_secret = "") {
            rewrite (.*) /session last;
        }

        rewrite (.*) /oauth_proxy last;
    }

    location /oauth_proxy {
        if ($oauth_token = "") {
            return 403;
        }

        if ($oauth_token_secret = "") {
            return 403;
        }

        set $proxy_uri "http://term.ie/oauth/example/echo_api.php?method=foo&bar=baz";
        proxy_set_header Authorization $oauth_signed_authenticated_call_header;
        proxy_pass $proxy_uri;
    }

    location /session {
        eval_override_content_type application/x-www-form-urlencoded;
        eval $oauth_token $oauth_token_secret {
            set $proxy_uri "http://term.ie/oauth/example/request_token.php";
            proxy_set_header Authorization $oauth_signed_request_token_header;
            proxy_pass $proxy_uri;
        }

        eval $oauth_token $oauth_token_secret {
            set $proxy_uri "http://term.ie/oauth/example/access_token.php";
            proxy_set_header Authorization $oauth_signed_access_token_header;
            proxy_pass $proxy_uri;
        }

        if ($oauth_token = "") {
            return 403;
        }

        if ($oauth_token_secret = "") {
            return 403;
        }

        session_store zone=test $oauth_token $oauth_token_secret expire=1d;

        add_header Location http://localhost:1982/;

        return 302;
    }
}
--- request
GET /
--- response_body_like: ^method=foo&bar=baz$
