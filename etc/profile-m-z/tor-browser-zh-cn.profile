# Firejail profile alias for torbrowser-launcher
# This file is overwritten after every install/update

# Persistent global definitions
include tor-browser-zh-cn.local

noblacklist ${HOME}/.tor-browser-zh-cn

mkdir ${HOME}/.tor-browser-zh-cn
whitelist ${HOME}/.tor-browser-zh-cn

# Redirect
include torbrowser-launcher.profile
