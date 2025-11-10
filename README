# Unlocky - CLI Password and Secret Manager/Vault

My first C-based project.

A lightweight, flexible and fast C-based cli password and secret manager/vault for Linux with encrypted storage (SQLite + libsodium), TOTP gen (SHA1/SHA256).


## Features
- **Encrypted Storage**: AES-GCM login, password, secret, cmd and totp blobs, Argon2 pw hash.
- **TOTP Support**: 6/8 digits, SHA1/SHA256, base32 decode.
- **CLI Commands**: add, get, list, modify, delete.
- **No User Management**: System-wide vault, per entry password for encrypt/decrypt.

## Install
### From Source (Arch/Debian)
```bash
git clone https://github.com/yourusername/unlocky.git
cd unlocky
sudo make install
unlocky list
```

## Commands

### ADD
#### Full Example
```bash
unlocky add -n test -l testlogin -p test1234 -c "sometestapp --login=%login% --password=%password% --totp=%totp% --secret=%secret%" -s "Some%Cool\$ecret" -o JBSWY3DPEHPK3PXP -od 8 -oh 1 -ob 2
```
#### Flags
**-n (required)**: Refers to the name of the entry, the name is used to identify the entry and has to be **unique**.  
**-l (optional)**: Refers to the stored login.  
**-p (required)**: Refers to the stored password (not to be confused with the master password used to encrypt an entry).  
**-c (optional)**: Refers to the stored command, the command has a uniqueness as you might have spotted in the example above.
The command itself can hold some of the values stored in the entry -> login as %login%, password as %password%, totp code as %totp% and secret as %secret%.
Those values will be replaced during the **get** command with the actual values.  
**-o (optional)**: The stored base32 encoded TOTP seed.  
**-od (optional)**: Digits configuration for the TOTP code, defaults to 6. Can be changed by passing 8.  
**-oh (optional)**: HMACSHA algo for the TOTP code, defaults to 1 (SHA1) as that is still currently the standard (although slowly fading out) but if you run into some more cutting edge apps which use
SHA256 you can change the configuration by passing 256.  
**-ob (optional)**: As mentioned above, the program expects a base32 encoded TOTP seed. If you for some reason don't need that, you can disabled the decoding by passing **1** or **2** if you want to enable the decoding.  

### GET
#### Example
```bash
unlocky get test
```
Retrieves the entry with the given name if the provided master password works, in the example above that would be the entry with the name **test**.
### LIST
#### Example
```bash
unlocky list
```
The list command will list all entries in the db without decryption and print only name, created at and updated at for each entry.
### MODIFY
#### Example
```bash
unlocky modify test -l newlogin
```
With the modify command you can change all the parameters except the name as it's unique and cannot be changed, if the provided master password works. The flags are the same as for the [ADD](#ADD) command.   
### DELETE
#### Example
```bash
unlocky delete test
```
This command will delete an entry from the db, given that the provided master password works.