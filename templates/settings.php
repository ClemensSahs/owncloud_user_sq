<form id="sql" action="#" method="post">
    <fieldset class="personalblock">
        <legend><?php echo $l->t('SQL'); ?></legend>
            <p><label for="sql_type"><?php echo $l->t('SQL Driver');?></label>
                <?php $db_driver = array('mysql' => 'MySQL', 'pgsql' => 'PostgreSQL');?>
                <select id="sql_type" name="sql_type">
                    <?php 
                        foreach ($db_driver as $driver => $name):
                            echo $_['sql_type'];
                            if($_['sql_type'] == $driver): ?>
                                <option selected="selected" value="<?php echo $driver; ?>"><?php echo $name; ?></option>
                            <?php else: ?>
                                <option value="<?php echo $driver; ?>"><?php echo $name; ?></option>
                            <?php endif;
                        endforeach; ?>
                </select>
            </p>

            <p><label for="sql_host"><?php echo $l->t('Host');?></label><input type="text" id="sql_host" name="sql_host" value="<?php echo $_['sql_host']; ?>"></p>
            <p><label for="sql_user"><?php echo $l->t('Username');?></label><input type="text" id="sql_user" name="sql_user" value="<?php echo $_['sql_user']; ?>" /></p>
            <p><label for="sql_database"><?php echo $l->t('Database');?></label><input type="text" id="sql_database" name="sql_database" value="<?php echo $_['sql_database']; ?>" /></p>
            <p><label for="sql_password"><?php echo $l->t('Password');?></label><input type="password" id="sql_password" name="sql_password" value="<?php echo $_['sql_password']; ?>" /></p>
            <p><label for="sql_table"><?php echo $l->t('Table');?></label><input type="text" id="sql_table" name="sql_table" value="<?php echo $_['sql_table']; ?>" /></p>
            <p><label for="sql_column_username"><?php echo $l->t('Username Column');?></label><input type="text" id="sql_column_username" name="sql_column_username" value="<?php echo $_['sql_column_username']; ?>" /></p>
            <p><label for="sql_column_password"><?php echo $l->t('Password Column');?></label><input type="text" id="sql_column_password" name="sql_column_password" value="<?php echo $_['sql_column_password']; ?>" /></p>
            <p><label for="sql_column_displayname"><?php echo $l->t('Real Name Column');?></label><input type="text" id="sql_column_displayname" name="sql_column_displayname" value="<?php echo $_['sql_column_displayname']; ?>" /></p>
            <p><label for="crypt_type"><?php echo $l->t('Encryption Type');?></label>
                <?php $crypt_types = array('md5' => 'MD5', 'md5crypt' => 'MD5 Crypt', 'cleartext' => 'Cleartext', 'mysql_encrypt' => 'mySQL ENCRYPT()', 'system' => 'System (crypt)', 'mysql_password' => 'mySQL PASSWORD()', 'joomla' => 'Joomla MD5 Encryption');?>
                <select id="crypt_type" name="crypt_type">
                    <?php 
                        foreach ($crypt_types as $driver => $name):
                            echo $_['crypt_type'];
                            if($_['crypt_type'] == $driver): ?>
                                <option selected="selected" value="<?php echo $driver; ?>"><?php echo $name; ?></option>
                            <?php else: ?>
                                <option value="<?php echo $driver; ?>"><?php echo $name; ?></option>
                            <?php endif;
                        endforeach; ?>
                </select>
            </p>            
            <p><label for="sql_column_active"><?php echo $l->t('User Active Column');?></label><input type="text" id="sql_column_active" name="sql_column_active" value="<?php echo $_['sql_column_active']; ?>" /></p>
            <p><label for="strip_domain"><?php echo $l->t('Strip Domain Part from Username');?></label><input type="checkbox" id="strip_domain" name="strip_domain" value="1"<?php if($_['strip_domain']) echo ' checked'; ?> title="Strip Domain Part from Username when logging in and retrieving username lists"></p>
            <p><label for="default_domain"><?php echo $l->t('Add default domain to Usernames');?></label><input type="text" id="default_domain" name="default_domain" value="<?php echo $_['default_domain']; ?>" /></p>
        <input type="hidden" name="requesttoken" value="<?php echo $_['requesttoken'] ?>" id="requesttoken" />
        <input type="submit" value="<?php echo $l->t('Save'); ?>" />
    </fieldset>
</form>
