# TIPS

## XKB

Switch layout by Caps lock:

add to /etc/default/keyboard
```
XKBOPTIONS="grp:caps_toggle,grp_led:caps,numpad:microsoft"
```

and do `sudo dpkg-reconfigure keyboard-configuration`
