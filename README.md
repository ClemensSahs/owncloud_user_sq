user_sql
========

Owncloud SQL authentification

This is plugin is heavily based on user_imap, user_pwauth, user_ldap and user_redmine!

Enable it in your Admin -> Apps section and configure your server's details.
Currently, it supports most of postfixadmin's encryption options, except dovecot and saslauthd.
It was tested and developed for a postfixadmin database.


Event
=====

This plugin is able to trigger events. You easiely can add your own listener to this events.
Currently we have the following events:
* "valid_user" - for default valid stack
* "valid_user.pre" - hight level logik or preloading of data (cache)
* "valid_user.post" - low level valid stack

the event object
----------------

* userId

OwnCloud userid / username

* userData

All possible importend user data

* eventStatus

set this false

* db.sql_table
* db.sql_column_username
* db.handle



using
-----

```php

use \Symfony\Component\EventDispatcher\Event;

class plugin {

    function registerMyListener () {
        $eventDispatcher = OC_USER_SQL::getEventDispatcher();
        $eventDispatcher->addListener('valid_user.pre', array($this,'validUserAddMoreUserDataToEvent'));
    }

    function validUserBySomethingAwesomeLogik (Event $event) {
        if ( false ) {
            $event->validStatus= false;
            $event->stopPropagation();
        }
    }
}
```


Credits
=======

  * Johan Hendriks provided his user_postfixadmin
  * Ed Wildgoose for fixing possible SQL injection vulnerability
