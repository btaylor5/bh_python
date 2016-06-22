#! /usr/bin/env python


# TODO: install a web framework into the frameworks directory so that we have
# a map for the crawler to look for leftover installation files
import Queue
import threading
import os
import urllib2

threads = 10

target = "http://www.blackhatpython.com"
directory = "./frameworks/"
filters = [".jpg", ".gif", "png", ".css"]


web_paths = Queue.Queue()

os.chdir(directory)
for r,d,f in os.walk("."):
    for files in f:
        remote_path = "%s/%s" % (r, files)
        if remote_path.startswith("."):
            remote_path = remote_path[1:]
        if os.path.splitext(files)[1] not in filters:
            web_paths.put(remote_path)

def test_remote():
    while not web_paths.empty():
        path = web_paths.get()
        url = "%s%s" % (target,path)

        request = urllib2.Request(url)
        try:
            response = urllib2.urlopen(request)
            content = response.read()

            print "[%d] => %s" % (response.code, path)
            response.close()
        except urllib2.HTTPError as error:
            print "Failed %s" % error.code
            pass

for i in xrange(threads):
    print "Spawning Thread: %d" % i
    t = threading.Thread(target=test_remote)
    t.start()
