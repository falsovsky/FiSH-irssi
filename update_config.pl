#!/usr/bin/env perl

use strict;
use warnings;

my $filepath;
my $filecontents;

if ( scalar @ARGV == 0 ) {
    if ( -e $ENV{"HOME"} . "/.irssi/blow.ini" ) {
        print " * " . $ENV{"HOME"} . "/.irssi/blow.ini exists! Use it? (y/n) ";
        my $resp = <>;
        if ($resp =~ m/y/i) {
            $filepath = $ENV{"HOME"} . "/.irssi/blow.ini";
        }
    }
}

if ( scalar @ARGV == 1 ) {
    $filepath = $ARGV[0];
}

if (!$filepath) {
    print "Usage: " . $0 . " [path to blow.ini]\n"
}

if ( -e $filepath ) {
    open ORIG, '<', $filepath or die "error opening $filepath: $!";
    open NEW, '>', "new_blow.ini" or die "error opening new_blow.ini to write";
    print " * Everything looks ok! Converting...\n";
    while (<ORIG>) {
        my $result = $_;;
        if ($result =~ m/\[.*?:(.*?)\]/) {
            my $lc = lc($1);
            $result =~ s/$1/$lc/g;
        }
        print NEW $result
    }
    close ORIG;
    close NEW;
    print " * Done!\n";
    print "Now just copy the newly generated \"new_blow.ini\" to ~/.irssi/blow.ini\n";
}

