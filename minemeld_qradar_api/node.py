import logging
import os
import shutil
import time
import uuid
import netaddr
from datetime import datetime, timedelta
from collections import deque

import gevent
import requests
import yaml
import ujson as json
from gevent.queue import Queue, Empty, Full
from netaddr import IPNetwork
from requests.exceptions import RequestException, HTTPError

from minemeld.ft import ft_states  #pylint: disable=E0401
from minemeld.ft.base import _counting  #pylint: disable=E0401
from minemeld.ft.actorbase import ActorBaseFT  #pylint: disable=E0401
from minemeld import __version__
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ENDPOINT_SUBMITBATCH = '/api/reference_data/sets/bulk_load/'
USER_AGENT= 'PaloAltoNetworks-MineMeld'
# Maximum number of batch upload
MAX_BATCH_SIZE=50
LOG = logging.getLogger(__name__)

class Output(ActorBaseFT):
    def __init__(self, name, chassis, config):
        super(Output, self).__init__(name, chassis, config)
        
        self._push_glet = None
        self._checkpoint_glet = None

    def configure(self):
        super(Output, self).configure()
        self.queue_maxsize = int(self.config.get('queue_maxsize', 100000))
        if self.queue_maxsize == 0:
            self.queue_maxsize = None
        self._queue = Queue(maxsize=self.queue_maxsize)
        
        self.URL = self.config.get('URL', None)
        self.Token = self.config.get('Token', None)
        self.SetIPv4 = self.config.get('Set_IPv4', None)
	self.SetURL = self.config.get('Set_URL', None)
        self.SetIPv6 = self.config.get('Set_IPv6', None)
	self.SetMD5 = self.config.get('Set_MD5', None)
        self.SetSHA1 = self.config.get('Set_SHA1', None)
        self.SetSHA256 = self.config.get('Set_SHA256', None)
        self.SetFilename = self.config.get('Set_Filename', None)
        self.SetDomain = self.config.get('Set_Domain', None)
	self.SetEmail = self.config.get('Set_Email', None)
   
    def connect(self, inputs, output):
        output = False
        super(Output, self).connect(inputs, output)
        
    def initialize(self):
        pass

    def rebuild(self):
        pass

    def reset(self):
        pass
        
    def _push_indicators(self, indicators):

        messages = list(indicators)
        LOG.debug('{} - _push_indicators message is: {}'.format(self.name, messages))
        IOC_IPv4 = []
	IOC_URL = []
	IOC_IPv6 = []
	IOC_MD5 = []
	IOC_SHA1 = []
	IOC_SHA256 = []
	IOC_Domain = []
	IOC_Email = []
	IOC_Filename = []
        for message in messages:
	     if message['type'] == 'IPv4':
	     	IOC_IPv4.append(message['value'])
	     elif message['type'] == 'URL':
		IOC_URL.append(message['value'])
             elif message['type'] == 'IPv6':
	        IOC_IPv6.append(message['value'])
             elif message['type'] == 'md5':
		IOC_MD5.append(message['value'])
             elif message['type'] == 'sha1':
		IOC_SHA1.append(message['value'])
             elif message['type'] == 'sha256':
		IOC_SHA256.append(message['value'])
             elif message['type'] == 'domain':
	        IOC_Domain.append(message['value'])
	     elif message['type'] == 'file.name':
		IOC_Filename.append(message['value'])
	     elif message['type'] == 'email-addr':
		IOC_Email.append(message['value'])

	if len(IOC_IPv4)>0:
	     result = requests.post(self.URL + ENDPOINT_SUBMITBATCH + self.SetIPv4,headers={'Content-Type': 'application/json','SEC': self.Token,'User-Agent': USER_AGENT},json=IOC_IPv4, verify=False)
	if len(IOC_URL)>0:
	     result = requests.post(self.URL + ENDPOINT_SUBMITBATCH + self.SetURL,headers={'Content-Type': 'application/json','SEC': self.Token,'User-Agent': USER_AGENT},json=IOC_URL, verify=False)
	if len(IOC_IPv6)>0:
	     result = requests.post(self.URL + ENDPOINT_SUBMITBATCH + self.SetIPv6,headers={'Content-Type': 'application/json','SEC': self.Token,'User-Agent': USER_AGENT},json=IOC_IPv6, verify=False)
        if len(IOC_MD5)>0:
	     result = requests.post(self.URL + ENDPOINT_SUBMITBATCH + self.SetMD5,headers={'Content-Type': 'application/json','SEC': self.Token,'User-Agent': USER_AGENT},json=IOC_MD5, verify=False)
        if len(IOC_SHA1)>0:
	     result = requests.post(self.URL + ENDPOINT_SUBMITBATCH + self.SetSHA1,headers={'Content-Type': 'application/json','SEC': self.Token,'User-Agent': USER_AGENT},json=IOC_SHA1, verify=False)
        if len(IOC_SHA256)>0:
	     result = requests.post(self.URL + ENDPOINT_SUBMITBATCH + self.SetSHA256,headers={'Content-Type': 'application/json','SEC': self.Token,'User-Agent': USER_AGENT},json=IOC_SHA256, verify=False)
        if len(IOC_Domain)>0:
	     result = requests.post(self.URL + ENDPOINT_SUBMITBATCH + self.SetDomain,headers={'Content-Type': 'application/json','SEC': self.Token,'User-Agent': USER_AGENT},json=IOC_Domain, verify=False)
        if len(IOC_Email)>0:
	     result = requests.post(self.URL + ENDPOINT_SUBMITBATCH + self.SetEmail,headers={'Content-Type': 'application/json','SEC': self.Token,'User-Agent': USER_AGENT},json=IOC_Email, verify=False)
        if len(IOC_Filename)>0:
	     result = requests.post(self.URL + ENDPOINT_SUBMITBATCH + self.SetFilename,headers={'Content-Type': 'application/json','SEC': self.Token,'User-Agent': USER_AGENT},json=IOC_Filename, verify=False)
	
	LOG.debug('{} - _push_indicators result is: {}'.format(self.name, result.text))

        result.raise_for_status()
    
    def _push_loop(self):
        while True:
            msg = self._queue.get()

            LOG.debug('{} - push_loop dequeued first indicator {!r}'.format(self.name, msg))

            artifacts = []
            artifacts.append(msg)	
            try:
                while len(artifacts) < MAX_BATCH_SIZE:
                    m = self._queue.get_nowait()
                    artifacts.append(m)
                    LOG.debug('{} - push_loop dequeued additional indicator {!r}'.format(self.name, m))                    
            except Empty:
                pass

            # Determine which indicators must be added and which ones must be deleted
            indicatorsToCreateUpdate=deque()

            for i in artifacts:
                indicatorsToCreateUpdate.append(i)

            LOG.info('{} - _push_loop has a total of {} indicators to create/update'.format(self.name, len(indicatorsToCreateUpdate)))


            # Retry loop for pushing indicators
            while True:
                retries = 0

                try:


                    if len(indicatorsToCreateUpdate) > 0:
                        LOG.debug('{} - Creating/Updating {} indicators'.format(self.name, len(indicatorsToCreateUpdate)))
                        
			try:
                            self._push_indicators(
                                indicators=indicatorsToCreateUpdate
                            )

                        # HTTP Error to track 4xx during the delete phase, with no retry
                        except HTTPError as e:
                            LOG.debug('{} - error creating/updating indicators - {}'.format(self.name, str(e)))
                            status_code = e.response.status_code

                            # If it's a 4xx, don't retry, else throw it up and go in the retry loop
                            if status_code >= 400 and status_code < 500:
                                LOG.error('{}: {} error in create/update request - {}'.format(self.name, status_code, e.response.text))
                                self.statistics['error.invalid_request'] += 1
                                # this way it will continue to the delete phase without retrying the create in the next loop
                                indicatorsToCreateUpdate=[]
                            else:
                                raise HTTPError(e)

                    # Successful loop
                    break

                # Graceful Exit
                except gevent.GreenletExit:
                    return

                # Other error, implement a retry logic
                # Note that if this hits during the delete phase, the createUpdate is never triggered
                except Exception as e:
                    LOG.exception('{} - error submitting indicators - {}'.format(self.name, str(e)))
                    self.statistics['error.submit'] += 1
                    retries += 1
                    if retries > 5:
                        break
                    gevent.sleep(120.0)

            gevent.sleep(0.1)
    
    def _encode_indicator(self, indicator, value, expired=False):
        type_ = value['type']

        if type_ not in ['IPv4','URL','sha1','md5','sha256','domain','email-addr','file.name','IPv6']:
            self.statistics['error.unhandled_type'] += 1
            raise RuntimeError('{} - Unhandled {}'.format(self.name, type_))
        
	expiration = datetime.utcnow() + timedelta(days=29)
        if expired:
            expiration = datetime.fromtimestamp(0)
        expiration = expiration.isoformat()

        indicators = []
        if type_ == 'IPv4' and '-' in indicator:
            a1, a2 = indicator.split('-', 1)
            r = netaddr.IPRange(a1, a2).cidrs()
            indicators = [str(i) for i in r ]
	else:
            indicators = [indicator]

        result = []
        for i in indicators:
	    r = {
		'expirationDateTime': expiration
	    }	
            if type_ == 'IPv4':
                parsed = netaddr.IPNetwork(i)
                if parsed.size == 1 and '/' not in i:
      		     r['type'] = type_
		     r['value'] = i
                elif '/32' in i:
                     r['type'] = type_
		     r['value'] = i.split('/',1)[0]
                else:
                    continue
            elif type_ == 'URL':
		 r['type'] = type_
		 r['value'] = i
	    elif type_ == 'IPv6':
		 r['type'] = type_
		 r['value'] = i
	    elif type_ == 'domain':
		 r['type'] = type_
		 r['value'] = i
            elif type_ == 'sha256':
		 r['type'] = type_
	         r['value'] = i
	    elif type_ == 'sha1':
		 r['type'] = type_
		 r['value'] = i
	    elif type_ == 'md5':
		 r['type'] = type_
		 r['value'] = i
	    elif type_ == 'file.name':
                 r['type'] = type_
		 r['value'] = i
	    elif type_ == 'email-addr':
                 r['type'] = type_
		 r['value'] = i
	    else:
                # Unsupported indicator type, should never reach this code
                continue

            LOG.debug('{!r} - add indicator {!r} to queue'.format(self.name, r))

            result.append(r)

        return result        
    
    def _checkpoint_check(self, source=None, value=None):
        t0 = time.time()

        while ((time.time() - t0) < 30) and self._queue.qsize() != 0:
            gevent.sleep(0.5)
        self._push_glet.kill()

        LOG.debug('{} - checkpoint with {} elements in the queue'.format(self.name, self._queue.qsize()))
        super(Output, self).checkpoint(source=source, value=value)

    @_counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        try:
            for i in self._encode_indicator(indicator, value, expired=False):
                self._queue.put(
                    i,
                    block=True,
                    timeout=0.001
                )
        except Full:
            self.statistics['error.queue_full'] += 1

    @_counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        if value is None:
            self.statistics['error.no_value'] += 1
            return

        try:
            for i in self._encode_indicator(indicator, value, expired=True):
                self._queue.put(
                    i,
                    block=True,
                    timeout=0.001
                )
        except Full:
            self.statistics['error.queue_full'] += 1

    @_counting('checkpoint.rx')
    def checkpoint(self, source=None, value=None):
        self.state = ft_states.CHECKPOINT
        self._checkpoint_glet = gevent.spawn(
            self._checkpoint_check,
            source,
            value
        )

    def length(self, source=None):
        return self._queue.qsize()

    def start(self):
        super(Output, self).start()

        self._push_glet = gevent.spawn(self._push_loop)

    def stop(self):
        super(Output, self).stop()

        if self._push_glet is not None:
            self._push_glet.kill()

        if self._checkpoint_glet is not None:
            self._checkpoint_glet.kill()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()

    @staticmethod
    def gc(name, config=None):
        ActorBaseFT.gc(name, config=config)
        shutil.rmtree(name, ignore_errors=True)
