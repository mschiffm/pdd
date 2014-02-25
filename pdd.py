#!/usr/bin/env python

"""Removes duplicate packets from a pcap using a tunable sliding window
"""

import os
import sys
import dpkt
import gzip
import argparse
from datetime import datetime
from collections import deque

def deduplicate_pcap(infile, outfile, pcap, window_size, verbosity):
    """Uses a sliding window of recently seen packets to remove duplicates.

    infile: original pcap file 
    outfile: newly created output file obeying the dpkt.pcap interface
    window_size: size of the sliding window of packets that get compared
    verbosity: level of verbosity as specified by the user

    """
    sliding_window = deque()
    tot_count      = 0
    pkt_count      = 0
    dup_count      = 0

    for ts, pkt in pcap:
        tot_count += 1
        for stored_pkt, stored_ts in sliding_window:
            if pkt == stored_pkt:
                dup_count += 1
                found_dup(pkt, ts, stored_ts, verbosity)
                break
        else:
            outfile.writepkt(pkt, ts)
            pkt_count += 1
            if len(sliding_window) >= window_size:
                # once deque is full pop off the rightmost (oldest) item
                sliding_window.pop()
            # add a new entry to the left side of the packet deque
            sliding_window.appendleft((pkt, ts))
    print >> sys.stderr, "Of %d total packets, I wrote %d and found %d duplicates" % (tot_count, pkt_count, dup_count)

def found_dup(pkt, ts, stored_ts, verbosity):
    """Generates message about the dup based on the verbosity flag.
    
    pkt: current packet from the pcap file
    ts: current packet timestamp
    stored_ts: timestamp from the matching packet stored in the sliding window
    verbosity: level of verbosity as specified by the user
 
    """

    eth = dpkt.ethernet.Ethernet(pkt)
    t1  = datetime.fromtimestamp(ts)
    t2  = datetime.fromtimestamp(stored_ts)
    if verbosity >= 2:
        print >> sys.stderr, "dup: %d byte packet at %s and %s: %s" % (len(pkt), t1, t2, repr(eth))
    elif verbosity == 1:
        print >> sys.stderr, "dup: %d byte packet at %s and %s" % (len(pkt), t1, t2)

if __name__ == '__main__':  

    parser = argparse.ArgumentParser(description = "parse a pcap file and remove duplicate packets, accepts gzip'd pcap files")
    parser.add_argument("-f", "--file", dest='infile_name', required = True,
            help = "pcap file to sift through")
    parser.add_argument("-w", "--window_size", dest = "window_size", type=int,
            default = 12,
            help = "size of the sliding packet window, a larger window may find more duplicate packets but will increase run-time, default is %(default)s")
    parser.add_argument("-v", "--verbose", dest = "verbosity",
            action = "count", default = False,
            help = "be more verbose when reporting, -vv be even more verbose")
    parser.add_argument("-o", "--outfile", dest = "outfile_name", type=str,
            help = "output filename") 
    parser.add_argument("-z", "--gzip", dest = "gzip", action = "count", 
            default = False,
            help = "gzip the output file")
    args = parser.parse_args()

    infile_ext = os.path.splitext(args.infile_name)
    if infile_ext[1] == ".gz" or infile_ext[1] == ".gzip":
        infile = gzip.open(args.infile_name, "rb")
    else:
        infile = open(args.infile_name, "rb")
    pcap       = dpkt.pcap.Reader(infile)
    if args.outfile_name:
        outfile_name = args.outfile_name
    else:
        outfile_name = args.infile_name + ".pdd." + str(os.getpid())
        if args.gzip >= 1:
            outfile_name = outfile_name + ".gz"
    if args.gzip >= 1:
        outfile    = dpkt.pcap.Writer(gzip.open(outfile_name, "wb")) 
    else:
        outfile    = dpkt.pcap.Writer(open(outfile_name, "wb"))

    print >> sys.stderr, "Using a window of %d, writing non-duplicates to %s" % (args.window_size, outfile_name)
    deduplicate_pcap(infile, outfile, pcap, args.window_size, args.verbosity)
    outfile.close()
    infile.close()
