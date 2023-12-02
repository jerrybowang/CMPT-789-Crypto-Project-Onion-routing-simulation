# CMPT 789 Crypto Project: Onion routing simulation

Group member
- Bo (Jerry) Wang
- Dahong (David) He

Presentation slides: TBD

## Development abstract:

In 30 days, our team will be dedicated to the development of a comprehensive Onion routing simulation. The primary objective of this simulation is to emulate the fundamental principles of Onion routing, encompassing relay-based communication and message encryption.

To accomplish this, we have adopted an object-oriented approach, addressing the modeling challenges of two classes, namely `Person` and `Router`. Leveraging discrete event simulation and event scheduling, we will integrate a cryptographic library to bolster the security aspects of the simulation. Furthermore, we plan to introduce simulation parameters, including the number of relays, potential eavesdropping scenarios, and an option for verbose mode.

Throughout the developmental phase, our focus will be on incremental progress and rigorous testing, ensuring the precision and reliability of our Onion routing simulation.  

## Implementation decision

#### Person

The class Person represents a person who can send and receive encrypted messages through a network of relays. This class can create and manage encryption keys, send and receive messages, and perform key exchanges with the network relays. It handles the encryption and decryption of messages and manages the process of sending and receiving messages through the relays. The class also contains variables to store the person's name, incoming messages, and encryption keys for communication with the relays. 

#### Router
The class Router represents a router in a network and includes methods for sending, replying, encrypting, decrypting, key exchange, and obtaining the public key. It also includes attributes for the name, capacity, inbox, received from, send to, encryption key, buffer, and RSA key. The decision to encapsulate these functionalities and attributes within the Router class allows for a modular and organized approach to managing the behavior and state of routers in the network. This makes the code easier to understand, maintain, and extend, and allows for reusable and testable components. Additionally, using a class allows for the instantiation of multiple router objects, each with their own state and behavior, providing a scalable solution for managing the network routers.


#### Event processing
The section 'Event processing' organizes the logic for processing various events such as key exchange, sending messages, transferring data through relays, receiving messages, replying, and handling errors. It leverages a queue-based event processing model to handle events in a sequential and organized manner. This decision to use a queue ensures that events are processed in the order they are received, allowing for a well-structured and predictable flow of operations.

The use of a class `Event_node` to encapsulate event types and data improves the modularity and readability of the event processing logic. By categorizing different types of events and their associated data, the code becomes easier to understand, maintain, and extend.

Additionally, the use of a match statement for event type handling enhances the readability of the code and makes it clear which actions are triggered based on the type of event. This approach makes the code more maintainable and allows for easy addition of new event types in the future.

## Executable
To run the main.py file, simply execute the file using a Python interpreter. Make sure that the required dependencies are installed.

Upon executing the main.py file, the user can expect the following behavior:

- The program will prompt the user to input the number of relays and the number of relays in a circuit, as well as whether to enable Eve and verbose mode.
- The program will initialize relays with random capacities and sort the relay pool by capacity.
- It will then choose relays for the circuit and initialize two persons: Alice and Bob.
- Key exchange, message sending, and event processing will be simulated based on the specified conditions and inputs.
- Throughout the simulation, the program will output information about the key exchange, message sending, and message receiving process, as well as any potential eavesdropping by "Eve" if enabled.
- The simulation will continue processing events until it reaches a conclusion, and the user will see the events being processed and the resulting messages being relayed between Alice and Bob.
