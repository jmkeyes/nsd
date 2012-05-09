#!/bin/sh

# Build a dnssexy distribution tar from the SVN repository.

# Abort script on unexpected errors.
set -e

# Remember the current working directory.
cwd=`pwd`

# Utility functions.
usage () {
    cat >&2 <<EOF
Usage $0: [-h] [-s] [-d SVN_root]
Generate a distribution tar file for dnssexy.

    -h           This usage information.
    -s           Build a snapshot distribution file.  The current date is
                 automatically appended to the current dnssexy version number.
    -rc <nr>     Build a release candidate, the given string will be added
		 to the version number (dnssexy-<version>rc<number>).
    -d SVN_root  Retrieve the dnssexy source from the specified repository.
EOF
    exit 1
}

info () {
    echo "$0: info: $1"
}

error () {
    echo "$0: error: $1" >&2
    exit 1
}

question () {
    printf "%s (y/n) " "$*"
    read answer
    case "$answer" in
        [Yy]|[Yy][Ee][Ss])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Only use cleanup and error_cleanup after generating the temporary
# working directory.
cleanup () {
    info "Deleting temporary working directory."
    cd $cwd && rm -rf $temp_dir
}

error_cleanup () {
    echo "$0: error: $1" >&2
    cleanup
    exit 1
}

replace_text () {
    (cp "$1" "$1".orig && \
        sed -e "s/$2/$3/g" < "$1".orig > "$1" && \
        rm "$1".orig) || error_cleanup "Replacement for $1 failed."
}

replace_all () {
    info "Updating '$1' with the version number."
    replace_text "$1" "@version@" "$version"
    info "Updating '$1' with today's date."
    replace_text "$1" "@date@" "`date +'%b %e, %Y'`"
}


SNAPSHOT="no"
RC="no"

# Parse the command line arguments.
while [ "$1" ]; do
    case "$1" in
        "-h")
            usage
            ;;
        "-d")
            SVNROOT="$2"
            shift
            ;;
        "-rc")
            RC="$2"
	    shift
            ;;
        "-s")
            SNAPSHOT="yes"
            ;;
        *)
            error "Unrecognized argument -- $1"
            ;;
    esac
    shift
done

# Check if SVNROOT is specified.
if [ -z "$SVNROOT" ]; then
    error "SVNROOT must be specified (using -d)"
fi

# Start the packaging process.
info "SVNROOT  is $SVNROOT"
info "SNAPSHOT is $SNAPSHOT"
info "RELEASE CANDIDATE is $RC"

#question "Do you wish to continue with these settings?" || error "User abort."


# Creating temp directory
info "Creating temporary working directory"
temp_dir=`mktemp -d nsd-dist-XXXXXX`
info "Directory '$temp_dir' created."
cd $temp_dir

info "Exporting source from SVN."
svn export "$SVNROOT" nsd || error_cleanup "SVN command failed"

cd nsd || error_cleanup "Dnssexy not exported correctly from SVN"

info "Building configure script (autoconf)."
autoconf || error_cleanup "Autoconf failed."

info "Building config.h.in (autoheader)."
autoheader || error_cleanup "Autoheader failed."

rm -r autom4te* || error_cleanup "Failed to remove autoconf cache directory."

info "Building lexer and parser."
echo "#include <config.h>" > zlexer.c || error_cleanup "Failed to create lexer."
flex -i -t zlexer.lex >> zlexer.c || error_cleanup "Failed to create lexer."
bison -y -d -o zparser.c zparser.y || error_cleanup "Failed to create parser."
echo "#include \"configyyrename.h\"" > configlexer.c || error_cleanup "Failed to create configlexer"
flex -i -t configlexer.lex >> configlexer.c || error_cleanup "Failed to create configlexer"
bison -y -d -o configparser.c configparser.y || error_cleanup "Failed to create configparser"

find . -name .c-mode-rc.el -exec rm {} \;
find . -name .cvsignore -exec rm {} \;
rm makedist.sh || error_cleanup "Failed to remove makedist.sh."

info "Determining dnssexy version."
version=`./configure --version | head -1 | awk '{ print $3 }'` || \
    error_cleanup "Cannot determine version number."
NAME=`./configure --version | head -1 | awk '{ print $1 }'`
name=`./configure --version | head -1 | awk '{ print $1 }' | tr A-Z a-z`

info "$NAME version: $version"

if [ "$RC" != "no" ]; then
    info "Building $NAME release candidate."
    version="${version}rc$RC"
    info "Release candidate version number: $version"
fi

if [ "$SNAPSHOT" = "yes" ]; then
    info "Building $NAME snapshot."
    version="$version-`date +%Y%m%d`"
    info "Snapshot version number: $version"
fi



replace_all doc/README
replace_all dnssexy.8.in
replace_all dnssexyc.8.in
replace_all dnssexy-notify.8.in
replace_all dnssexy-checkconf.8.in
replace_all dnssexy-patch.8.in
replace_all dnssexy-xfer.8.in
replace_all zonec.8.in
replace_all dnssexy.conf.5.in

info "Renaming $NAME directory to $name-$version."
cd ..
mv nsd $name-$version || error_cleanup "Failed to rename $NAME directory."

tarfile="../$name-$version.tar.gz"

if [ -f $tarfile ]; then
    (question "The file $tarfile already exists.  Overwrite?" \
        && rm -f $tarfile) || error_cleanup "User abort."
fi

info "Moving dnssexy-setup to contrib directory"
mv $name-$version/tpkg/dnssexy-setup $name-$version/contrib/dnssexy-setup

info "Deleting the tpkg directory"
rm -rf $name-$version/tpkg/

info "Creating tar $name-$version.tar.gz"
tar czf ../$name-$version.tar.gz $name-$version || error_cleanup "Failed to create tar file."

cleanup

case $OSTYPE in
        linux*)
                sha=`sha1sum $name-$version.tar.gz |  awk '{ print $1 }'`
                ;;
        FreeBSD*)
                sha=`sha1  $name-$version.tar.gz |  awk '{ print $5 }'`
                ;;
	*)
                sha=`sha1sum $name-$version.tar.gz |  awk '{ print $1 }'`
                ;;
esac
echo $sha > $name-$version.tar.gz.sha1

info "$NAME distribution created successfully."
info "SHA1sum: $sha"

