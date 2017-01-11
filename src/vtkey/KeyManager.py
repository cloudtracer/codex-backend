from redis import Redis
from redis_semaphore import Semaphore
from threading import Thread
import urllib2
import time
import os
path=os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..'))
import sys
sys.path.insert(0, path)
from db_pool import *
from datetime import timedelta

class KeyManager():
    def __init__(self):
        self.semaphore = Semaphore(Redis(host=env.get('redis').get('host')), count=1, namespace='example')

    def check_keys_in_secrets(self):
        if ((env.get('vt_public_apikey') is None or env.get('vt_public_apikey') == "" ) and
                (env.get('vt_private_apikey') is None or env.get('vt_private_apikey') == "")):
            return False
        else:
            return True

    def get_keys_from_secrets(self):
        if not self.check_keys_in_secrets():
            return {"public": [], "private": []}
        else:
            keys = {}
            for p in ["public", "private"]:
                keys[p] = []
                config_str = 'vt_'+p+'_apikey'
                if type(env.get(config_str))==list:
                    keys[p].extend(env.get(config_str))
                elif isinstance(env.get(config_str),basestring):
                    keys[p].append(env.get(config_str))
            return keys


    def get_key(self, operation, priority=None):
        if operation != "av_analysis" and operation != "download_sample":
            raise ValueError("operation invalid")
        if priority is not None and priority != "low" and priority != "high":
            raise ValueError("priority invalid")
        if priority is None:
            priority = "low"
        print "waiting for semaphore"
        keys = self.get_keys_from_secrets()
        if len(keys["public"])==0 and len(keys["private"])==0:
            print "No VT keys"
            return None
        with self.semaphore:
            if(db.vtkeys.find().count()==0):
                db.vtkeys.insert({"doc": 1})
            doc = db.vtkeys.find({"doc": 1})
            if doc.count() != 1:
                raise ValueError("doc.count() is different from 1. it did not create a doc in vtkeys collection?")
            doc = doc[0] # get first and only document
            if operation == "av_analysis":
                timeleft_vec = []
                for key in keys["public"]: # we try to find a public VT api key
                    key_data = doc.get(key)
                    if key_data is None: # first time a key is used.
                        new_document = { key: { "total": 1, "daily": 1, "last_modified": "$currentDate" } }
                        db.update_one({"doc": 1},{"$set": new_document },upsert=True)
                        return {"key": key}
                    else: # not the first time the key is used.
                        if(key_data.get(last_modified) < ( datetime.now() - timedelta(seconds=15) )):
                            # key is ready to be used
                            doc_to_update = { key: { "total": key_data.get('total')+1,
                                "daily": key_data.get('daily')+1, "last_modified": "$currentDate"}}
                            db.update_one({"doc": 1},{"$set": doc_to_update })
                            return {"key": key}
                        else: # key is not ready to be used.
                            if priority == "low":
                                # add timeleft in seconds to array
                                timeleft_in_seconds = (key_data.get(last_modified)-(datetime.now-timedelta(seconds=15))).seconds
                                timeleft_vec.append({"key": key, "timeleft": timeleft_in_seconds })
                if priority == "low": #if priority low, we should ask the worker to wait.
                    print "no public keys available right now"
                    # so we don't spend a credit from the private key.
                    # we should return the smallest timeleft.
                    timeleft_sorted = sorted(timeleft_vect,key=lambda k: k["timeleft"])
                    return {"key": None, "timeleft": timeleft_sorted[0].get('timeleft')}

            if operation=="download_sample" or (operation=="av_analysis" and priority=="high"):
            # we should return the private key that has more credits.
                private_keys_vec = []
                for key in keys["private"]:
                    key_data = doc.get(key)
                    if key_data is None: #first time the private key is used
                        new_document = { key: {"total": 1, "daily": 1, "last_modified": "$currentDate"}}
                        db.update_one({"doc": 1},{"$set": new_document})
                        return {"key": key}
                    else:
                        private_keys_vec.append({"key": key, "daily": key_data.get('daily')})
                private_keys_sorted = sorted(private_keys_vec,key=lambda k: k["daily"])
                return {"key": private_keys_sorted[0].get('key')}
            print str(doc)

            print "sleep 5 seconds"
            time.sleep(5)
        print "left semaphore"
