#!/bin/sh

if [ -z "$1"]; then
    echo "Please specific path to click package"
    exit 1
fi
c="$1"
if [ ! -f "$c" ]; then
    echo "Could not find '$c'"
    exit 1
fi

rc="0"
set_rc() {
    # return worst offending rc
    if [ "$1" = "1" ]; then
        if [ "$rc" != "2" ]; then
            rc="$1"
        fi
    elif [ "$1" = "2" ]; then
        rc="$1"
    fi

}

./show-click-files "$c" || set_rc "$?"

echo ""
echo "= check-lint ="
./check-lint "$c" || set_rc "$?"

echo ""
echo "= check-desktop ="
./check-desktop "$c" || set_rc "$?"

echo ""
echo "= check-security ="
./check-security "$c" || set_rc "$?"

echo ""
echo ""
if [ "$rc" = "1" ]; then
    echo "** Warnings found **"
elif [ "$rc" = "2" ]; then
    echo "** Errors found **"
fi

echo -n "$c: "
if [ "$rc" = "0" ]; then
    echo "pass"
else
    echo "FAIL"
fi

exit $rc
