# imports 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import random
from queue import Queue

# global vars
# ip list is a key value pair of the name and the reference 
IP_lists = {}
# The splitting characters for our simplified packet
splitting_chars = "|*-*|"
# The list of relays
relay_pool = []

# Event Queue
event_queue = Queue()

# simulation end signal
END_signal = False

# verbose signal
verbose = False

# Eve signal: sending phase, reply phase
Eve_signal = [False, False]

# helper functions
def rsa_key_gen():
  key = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
  return key

def rsa_enc(key, plaintext):
  enc = key.encrypt(
      plaintext,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )
  return enc

def rsa_dec(key, ciphertext):
  dec = key.decrypt(
      ciphertext,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )
  return dec

# return the bit string
def b_format(text: str):
  return bytes(text, "utf-8")

# ----------------

class Router:
  def __init__(self, name:str, capacity:int):
    self.name = name
    self.capacity = capacity
    self.inbox: bytes
    self.received_from: str
    self.send_to: str
    self.key: bytes
    self.buffer: bytes
    self.f: Fernet  # the encryption module
    self.rsa_key = rsa_key_gen()

  def send(self):
    IP_lists[self.send_to].inbox = self.buffer
    IP_lists[self.send_to].received_from = self.name

  def reply(self):
    IP_lists[self.received_from].inbox = self.buffer

  def encrypt(self):
    self.f = Fernet(self.key)
    self.buffer = self.f.encrypt(self.inbox)

  def decrypt(self):
    self.f = Fernet(self.key)
    result = self.f.decrypt(self.inbox)
    
    # if the result contains the splitting_chars
    if b_format(splitting_chars) in result:
      result = result.split(b_format(splitting_chars))
      self.send_to = result[0].decode()
      self.buffer = result[1]
    else:
      # it's a key exchange
      self.key = result

  def get_public_key(self):
    return self.rsa_key.public_key()

  def key_exchange(self):
    self.key = rsa_dec(self.rsa_key, self.inbox)

class Person:
  def __init__(self, name:str):
    self.name = name
    self.inbox: bytes
    self.received_from: str
    self.buffer: bytes
    self.f: Fernet  # the encryption module
    self.received_msg: str
    # 0: guard relay; 1: middle; 2: exit
    self.keys = []
    self.relay_public_keys = []
    self.relays = []


  def send(self, message:str, recipient:str):
    # construct packets for exit relay
    packets = b_format(recipient) + b_format(splitting_chars) + b_format(message)
    self.f = Fernet(self.keys[-1])
    enc = self.f.encrypt(packets)
    
    # construct exchange packet
    num_of_relays = len(self.relays)
    if num_of_relays > 1:
      for i in range(num_of_relays - 2, -1, -1):
        packets = b_format(self.relays[i+1]) + b_format(splitting_chars) + enc
        self.f = Fernet(self.keys[i])
        enc = self.f.encrypt(packets)

    # sent it to the guard relay
    IP_lists[self.relays[0]].inbox = enc
    IP_lists[self.relays[0]].received_from = self.name

  def decrypt(self):
    self.f = Fernet(self.keys[0])
    self.buffer = self.f.decrypt(self.inbox)

    num_of_relays = len(self.relays)
    for i in range(1, num_of_relays):
      self.f = Fernet(self.keys[i])
      self.buffer = self.f.decrypt(self.buffer)

    # decode it
    self.received_msg = self.buffer.decode()

  def reply(self, msg: str):
    IP_lists[self.received_from].inbox = msg.encode()

  def key_exchange(self, relay: str):
    # append new key
    self.keys.append(Fernet.generate_key())
    self.relays.append(relay)
    self.relay_public_keys.append(IP_lists[relay].get_public_key())
    
    # construct exchange packet
    num_of_relays = len(self.relay_public_keys)
    enc = rsa_enc(self.relay_public_keys[-1], self.keys[-1])
    if num_of_relays > 1:
      for i in range(num_of_relays - 2, -1, -1):
        packets = (self.relays[i + 1] + splitting_chars).encode() + enc
        self.f = Fernet(self.keys[i])
        enc = self.f.encrypt(packets)
        
    IP_lists[self.relays[0]].inbox = enc
    IP_lists[self.relays[0]].received_from = self.name



# Event processing
class Event_node:
  def __init__(self, type: str, data):
    self.type = type
    self.data = data

def event_processor():
  # specify global variable within a function
  global END_signal
  global event_queue
  global Eve_signal
  global verbose
  # check if event_q is non empty
  if event_queue.empty():
    END_signal = True
    return

  event_node = event_queue.get()
  match event_node.type:
    case "key_exchange":
      print("Starting key exchange with each relays:")
      target_relay = event_node.data[0]
      sender = IP_lists["Alice"]
      if verbose:
        print(f"{sender.name} start key exchange with {target_relay}")
      sender.key_exchange(target_relay)
      if verbose:
        print(f"{sender.name} finished key exchange with {target_relay}\n")
      IP_lists[target_relay].key_exchange()
      
      # now build the rest of the key exchange
      for i in event_node.data[1:]:
        if verbose:
          print(f"{sender.name} start key exchange with {i}")
        sender.key_exchange(i)
        for router in sender.relays[:-1]:
          if verbose:
            print(f"{router} start transferring the message")
          IP_lists[router].decrypt()
          IP_lists[router].send()
        if verbose:
          print(f"{sender.name} finished key exchange with {i}\n")
        IP_lists[i].key_exchange()
      print("Key exchange complete\n")
      
    case "send message":
      print("Alice wants to send a message to Bob")
      msg = input("Enter the message: ")
      IP_lists["Alice"].send(msg, "Bob")
      # schdule following event
      event_queue.put(Event_node("send transfer", event_node.data))
      
    case "send transfer":
      # check if we already arrived
      if event_node.data == []:
        event_queue.put(Event_node("received", []))
      else:
        # Eve
        number = len(event_node.data)
        if Eve_signal[0] and random.randint(0,number) == 0:
          print(f"\nEve eavesdropped the message on {event_node.data[0]}!")
          print(IP_lists[event_node.data[0]].inbox, "\n")
          Eve_signal[0] = False

        # let the realy transfer the message
        if verbose:
          print(f"{IP_lists[event_node.data[0]].name} start transferring the message")
        IP_lists[event_node.data[0]].decrypt()
        IP_lists[event_node.data[0]].send()
        
        # schdule the following event
        event_queue.put(Event_node("send transfer", event_node.data[1:]))
        
    case "received":
      print("Bob received a message from Alice")
      print("Bob received: " + IP_lists["Bob"].inbox.decode())
      print("\nBob wants to reply a message to Alice")
      msg = input("Enter the message: ")
      IP_lists["Bob"].reply(msg)
      
      # schdule the following event
      relays = IP_lists["Alice"].relays.copy()
      relays.reverse()
      event_queue.put(Event_node("send reply", relays))
      
    case "send reply":
      # check if we already arrived
      if len(event_node.data) == 0:
        event_queue.put(Event_node("replied", []))
      else:
        # let the realy transfer the message
        IP_lists[event_node.data[0]].encrypt()

        # Eve
        number = len(event_node.data)
        if Eve_signal[1] and random.randint(0,number) == 0:
          print(f"\nEve eavesdropped the message on {event_node.data[0]}!")
          print(IP_lists[event_node.data[0]].buffer, "\n")
          Eve_signal[1] = False

        # let the realy transfer the message
        if verbose:
          print(f"{IP_lists[event_node.data[0]].name} start transferring the message")
        IP_lists[event_node.data[0]].reply()
        
        # schdule the following event
        event_queue.put(Event_node("send reply", event_node.data[1:]))
        
    case "replied":
      print("\nAlice received a reply from Bob")
      IP_lists["Alice"].decrypt()
      print("Alice received: \n" + IP_lists["Alice"].received_msg)
      
    case _:
      print("event_processor: error, undefined type")
      END_signal = True
  return



# ------

def main():
  # ask user input
  num_of_relays = int(input("Number of relays: "))
  num_of_relays_in_circuit = int(input("Number of relays in a circuit: "))
  eve_enable = input("Enable Eve? (y/n): ").lower()
  verbose_mode = input("Verbose mode? (y/n): ").lower()
  
  # input validation
  validation_flag = True
  if num_of_relays < 3:
    print("Input invalid: Number of relays < 3")
    validation_flag = False
  if num_of_relays_in_circuit < 3:
    print("Input invalid: Number of relays in a circuit < 3")
    validation_flag = False
  if eve_enable not in ["y", "n"]:
    print("Input invalid: Enable Eve must be 'y' or 'n'")
    validation_flag = False
  if verbose_mode not in ["y", "n"]:
    print("Input invalid: Verbose mode must be 'y' or 'n'")
    validation_flag = False
  if validation_flag is False:
    return

  # iniatialization
  # iniatialize relays with random capasicy
  for i in range(num_of_relays):
    relay = Router(f"R{i}", random.randint(1, 20))
    relay_pool.append(relay)
    # also add it to IP_lists
    IP_lists[f"R{i}"] = relay

  # sort the relay_pool by capacity
  relay_pool.sort(key=lambda x: x.capacity, reverse=True)

  print("The following relays has been created:")
  for i in relay_pool:
    print(f"Relay: {i.name}; capacity: {i.capacity}")
    
  # choose the relay
  chosen_relay = []
  for i in range(num_of_relays_in_circuit):
    chosen_relay.append(relay_pool[i].name)

  print("\nThe following relays are chosen for the circuit:")
  print(chosen_relay, "\n")
  
  # iniatialize Alice and Bob
  Alice = Person("Alice")
  Bob = Person("Bob")
  IP_lists["Alice"] = Alice
  IP_lists["Bob"] = Bob

  # iniatialize signals
  global Eve_signal
  global verbose
  Eve_signal = [True, True] if eve_enable == "y" else [False, False]
  verbose = bool(verbose_mode == "y")

  # initialize event queue
  global event_queue
  global END_signal
  event_queue.put(Event_node("key_exchange",chosen_relay))
  event_queue.put(Event_node("send message",chosen_relay))

  while not END_signal:
    event_processor()



if __name__ == "__main__":
  main()
