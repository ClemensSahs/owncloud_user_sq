<?php

/**
* ownCloud - user_sql
*
* @author Andreas Böhler
* @copyright 2012 Andreas Böhler <andreas (at) aboehler (dot) at>
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
* License as published by the Free Software Foundation; either
* version 3 of the License, or any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU AFFERO GENERAL PUBLIC LICENSE for more details.
*
* You should have received a copy of the GNU Affero General Public
* License along with this library.  If not, see <http://www.gnu.org/licenses/>.
*
*/

require_once('apps/user_sql/user_sql.php');

OC_App::registerAdmin('user_sql','settings');

// define IMAP_DEFAULTs
define('OC_USER_BACKEND_SQL_DEFAULT_HOST', 'localhost');
define('OC_USER_BACKEND_SQL_DEFAULT_USER', 'mail_admin');
define('OC_USER_BACKEND_SQL_DEFAULT_DB', 'postfixadmin');
define('OC_USER_BACKEND_SQL_DEFAULT_PASSWORD', 'password');
define('OC_USER_BACKEND_SQL_DEFAULT_TABLE', 'users');
define('OC_USER_BACKEND_SQL_DEFAULT_PW_COLUMN', 'password');
define('OC_USER_BACKEND_SQL_DEFAULT_USER_COLUMN', 'username');
define('OC_USER_BACKEND_SQL_DEFAULT_DRIVER', 'mysql');

// register user backend
OC_User::registerBackend('SQL');
OC_User::useBackend('SQL');

// add settings page to navigation
$entry = array(
        'id' => "user_sql_settings",
        'order'=>1,
        'href' => OC_Helper::linkTo( "user_sql", "settings.php" ),
        'name' => 'SQL'
);


