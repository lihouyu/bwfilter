###
#
# BWFilter - Bad Words Filter
#
# Bad word filter for Apache2.x with mod_perl2
# 
# Copyright (c) 2009 HouYu Li <karadog@gmail.com> 
# 
# The filter is used for disabling web pages that containing specified
# words in content or URL. Apache 2 + mod_perl 2 is required for running
# this program. For details, see README.
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# 
###

package BadWordsFilter;

use strict;
use warnings FATAL => 'all';

use Apache2::Filter();
use Apache2::RequestRec();

use APR::Table();
use APR::Bucket();
use APR::Brigade();

use Encode qw(from_to);;

use Apache2::Const -compile => qw(OK);
use APR::Const     -compile => ':common';

use constant BUFF_LEN => 8192;

################################################
# You may change the default configuration file location here
my $configuration;
if ($^O eq "MSWin32") {
    $configuration = "C:/bwf.conf";
} else {
    $configuration = "/etc/bwf.conf";
}
#
################################################

sub read_config {
    my $fc = shift;

    our $ret = 1;

    {   # Put config data into a separate namespace
        package Config;

        # Process the contents of the config file
        my $rc = do($fc);

        # Check for errors
        if ($@) {
            $::ret = 0;
        } elsif (!defined($rc)) {
            $::ret = 0;
        } elsif (!$rc) {
            $::ret = 0;
        }
    }

    return ($ret);
}

# Read configurations
my $rc = read_config($configuration);

# Prepare logfile now
my $log_str;
my $f_log;
if ($Config::Params{"loglevel"} > 0) {
    open($f_log, ">>", $Config::Params{"logfile"}) or die("BadWordsFilter: Unable to open log file $Config::Params{'logfile'}!");
}

sub to_log {
    if ($Config::Params{"loglevel"} > 0) {
        my $s_log = shift;

        (my $second, my $minute, my $hour, my $dayOfMonth, my $monthIndex, 
            my $yearOffset, my $dayOfWeek, my $dayOfYear, my $daylightSavings) = localtime();
        my $year = 1900 + $yearOffset;
        my $month = $monthIndex + 1;
        my $log_time = "$year-$month-$dayOfMonth $hour:$minute:$second";

        print $f_log $log_time." $s_log\r\n";
    }
}

# Seed holders
my @whitelist;
my @badwords;
my @badurls;

my $msg_badwords = "";
my $msg_badurls = "";

# Get white list first
if (-e $Config::Params{"whitelist"}) {
    open(my $f_whitelist, "<", $Config::Params{"whitelist"});
    while (<$f_whitelist>) {
        if (!/^\#/ && !/^\s*$/) {
            push(@whitelist, $_);
        }
    }
    close($f_whitelist);

    if ($Config::Params{"loglevel"} >= 2) {
        $log_str = "whitelist loaded!";
        if (@whitelist == 0) {
            $log_str .= " BUT with nothing in it!";
        }
        to_log($log_str);
    }
} else {
    if ($Config::Params{"loglevel"} >= 2) {
        to_log("whitelist nothing to load!");
    }
}

# Get bad words if it's enabled
if ($Config::Params{"enable_badwords_filter"} eq "yes") {
    if (-e $Config::Params{"badwords"}) {
        open(my $f_badwords, "<", $Config::Params{"badwords"});
        while (<$f_badwords>) {
            if (!/^\#/ && !/^\s*$/) {
                push(@badwords, $_);
            }
        }
        close($f_badwords);

        if ($Config::Params{"loglevel"} >= 2) {
            $log_str = "badwords loaded!";
            if (@badwords == 0) {
                $log_str .= " BUT with nothing in it!";
            }
            to_log($log_str);
        }
    } else {
        if ($Config::Params{"loglevel"} >= 2) {
            to_log("badwords nothing to load!");
        }
    }

    # Load messages
    if (-e $Config::Params{"badwords_msg"}) {
        open(my $f_badwords_msg, "<", $Config::Params{"badwords_msg"});
        while (<$f_badwords_msg>) {
            $msg_badwords .= $_;
        }
        close($f_badwords_msg);

        if ($Config::Params{"loglevel"} >= 2) {
            $log_str = "badwords message loaded!";
            if ($msg_badwords eq "") {
                $log_str .= " BUT with nothing in it!";
            }
            to_log($log_str);
        }
    } else {
        if ($Config::Params{"loglevel"} >= 2) {
            to_log("badwords message nothing to load!");
        }
    }
}

# Get bad urls if it's enabled
if ($Config::Params{"enable_badurls_filter"} eq "yes") {
    if (-e $Config::Params{"badurls"}) {
        open(my $f_badurls, "<", $Config::Params{"badurls"});
        while (<$f_badurls>) {
            if (!/^\#/ && !/^\s*$/) {
                push(@badurls, $_);
            }
        }
        close($f_badurls);

        if ($Config::Params{"loglevel"} >= 2) {
            $log_str = "badurls loaded!";
            if (@badurls == 0) {
                $log_str .= " BUT with nothing in it!";
            }
            to_log($log_str);
        }
    } else {
        if ($Config::Params{"loglevel"} >= 2) {
            to_log("badurls nothing to load!");
        }
    }

    # Load messages
    if (-e $Config::Params{"badurls_msg"}) {
        open(my $f_badurls_msg, "<", $Config::Params{"badurls_msg"});
        while (<$f_badurls_msg>) {
            $msg_badurls .= $_;
        }
        close($f_badurls_msg);

        if ($Config::Params{"loglevel"} >= 2) {
            $log_str = "badurls message loaded!";
            if ($msg_badurls eq "") {
                $log_str .= " BUT with nothing in it!";
            }
            to_log($log_str);
        }
    } else {
        if ($Config::Params{"loglevel"} >= 2) {
            to_log("badurls message nothing to load!");
        }
    }
}

sub flatten_bb {
    my ($bb) = shift;

    my $seen_eos = 0;

    my @data;
    for (my $b = $bb->first; $b; $b = $bb->next($b)) {
        $seen_eos++, last if $b->is_eos;
        $b->read(my $bdata);
        push @data, $bdata;
    }
    return (join('', @data), $seen_eos);
}

sub handler {
    my ($f, $b) = @_;

    my $hostname = $f->r->hostname;
    my $uri = $f->r->uri;

    # Check whether the requested host is in whitelist
    my $res_ignored = 0;
    if (@whitelist > 0) {
        foreach (@whitelist) {
            if (index($hostname, $_) >= 0) {
                $res_ignored = 1;
                if ($Config::Params{"loglevel"} >= 1) {
                    to_log("$hostname ignore whitelist $hostname");
                }
                last;
            }
        }
    }

    # Ignore specified file with given extension
    my $ignored_ext_pat = "\\.($Config::Params{'ignored_ext'})\$";
    if ($uri =~ /$ignored_ext_pat/i) {
        $res_ignored = 1;
        if ($Config::Params{"loglevel"} >= 1) {
            to_log("$hostname ignore ignext $uri");
        }
    }

    if ($res_ignored == 0) { # The site content should be checked
        my $ctx = $f->ctx;

        my $output = exists($ctx->{data}) ? $ctx->{data} : '';
        $ctx->{invoked}++;
        my ($b_data, $seen_eos) = flatten_bb($b);
        $output .= $b_data if $b_data;

        if ($seen_eos) {
            my $has_badurl = 0;
            my $has_badword = 0;

            # Check request Hostname/URI first if enabled
            if ($Config::Params{"enable_badurls_filter"} eq "yes") {
                foreach (@badurls) {
                    if (index($uri, $_) >= 0 || index($hostname, $_) >= 0) {
                        $has_badurl = 1;
                        if ($Config::Params{"loglevel"} >= 1) {
                            to_log("$hostname badurl $_ $uri");
                        }
                        last;
                    }
                }
            }

            # Check bad words if enabled
            if ($Config::Params{"enable_badwords_filter"} eq "yes" && $has_badurl == 0) {
                foreach (@badwords) {
                    if (index($output, $_) >= 0) {
                        $has_badword = 1;
                        if ($Config::Params{"loglevel"} >= 1) {
                            to_log("$hostname badword $_ $uri $Config::Params{'badwords_charset'}");
                        }
                        last;
                    }
                }

                if ($has_badword == 0) {
                    foreach (@{$Config::Params{"try_charsets"}}) {
                        my $test_charset = $_;
                        foreach (@badwords) {
                            my $new_badword = $_;
                            from_to($new_badword, $Config::Params{"badwords_charset"}, $test_charset);
                            if (index($output, $new_badword) >= 0) {
                                $has_badword = 1;
                                if ($Config::Params{"loglevel"} >= 1) {
                                    to_log("$hostname badword $_ $uri $test_charset");
                                }
                                last;
                            }
                        }

                        last if ($has_badword == 1);
                    }
                }
            }

            # Print out put according to check result
            if ($has_badurl == 1 || $has_badword == 1) {
                $f->r->content_type("text/plain; charset=$Config::Params{'msg_charset'}");

                $output = "";

                if ($has_badurl == 1) {
                    $output .= $msg_badurls;
                }
                if ($has_badword == 1) {
                    $output .= $msg_badwords;
                }
            }

            my $len = length($output);
            $f->r->headers_out->set('Content-Length', $len);
            $f->print($output) if $output;

            undef($output) if $output;
        } else {
            # store context for all but the last invocation
            $ctx->{data} = $output;
            $f->ctx($ctx);
        }
    } else { # The site content is ignored
        while ($f->read(my $buffer, BUFF_LEN)) {
            $f->print($buffer);
        }
    }

    return Apache2::Const::OK;
}

#close($f_log);

1;
