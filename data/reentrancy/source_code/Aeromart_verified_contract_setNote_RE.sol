/*
 * ===== SmartInject Injection Details =====
 * Function      : setNote
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding two external calls: one for product validation before state updates and another for observer notification after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first become the owner and set up malicious contracts as productRegistry and/or noteObserver addresses through separate transactions.
 * 
 * 2. **State Accumulation**: The vulnerability exploits the fact that state changes (note.productID and note.textOrImage) persist between the two external calls, creating a window where the contract state is inconsistent.
 * 
 * 3. **Exploitation Sequence**:
 *    - Transaction 1: Attacker sets malicious productRegistry contract
 *    - Transaction 2: Attacker sets malicious noteObserver contract  
 *    - Transaction 3: Attacker calls setNote(), triggering the vulnerable sequence:
 *      - External call to productRegistry.validateProduct() can reenter setNote()
 *      - State gets updated (note.productID, note.textOrImage)
 *      - External call to noteObserver.onNoteUpdated() can reenter again
 *      - Multiple reentrancy points create opportunities for state manipulation
 * 
 * 4. **Stateful Nature**: The vulnerability requires the persistent state of productRegistry and noteObserver addresses to be set in previous transactions, and the notes mapping state changes accumulate across multiple reentrant calls.
 * 
 * 5. **Realistic Attack Vector**: The malicious contracts can manipulate the notes data by reentering at different points, potentially causing data corruption or inconsistent state that builds up over multiple transactions.
 * 
 * The vulnerability is only exploitable through this multi-transaction sequence and requires state persistence between calls, making it a genuine stateful, multi-transaction reentrancy vulnerability.
 */
pragma solidity ^0.4.22;

contract Owned {
    address owner;
    
    function constructor() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}

// Declare interfaces for external contracts used in Aeromart
interface IProductRegistry {
    function validateProduct(bytes32 _productID) external;
}

interface INoteObserver {
    function onNoteUpdated(uint256 _id, bytes32 _productID, string _textOrImage) external;
}

contract Aeromart is Owned {
    
    struct Note {
        bytes32 productID;
        string textOrImage;
    }
    
    uint public notesLength;
    mapping (uint256 => Note) public notes;
    
    // Add state variables for external contract addresses
    address public productRegistry;
    address public noteObserver;
   
    event noteInfo(
        bytes32 productID,
        string textOrImage
    );
    
    function addNote(bytes32 _productID, string _textOrImage) onlyOwner public returns (uint) {
        Note storage note = notes[notesLength];
        
        note.productID = _productID;
        note.textOrImage = _textOrImage;
		
        emit noteInfo(_productID, _textOrImage);
        
        notesLength++;
        return notesLength;
    }
    
    function setNote(uint256 _id, bytes32 _productID, string _textOrImage) onlyOwner public {
        Note storage note = notes[_id];
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to product registry for validation before state updates
        if (productRegistry != address(0)) {
            IProductRegistry(productRegistry).validateProduct(_productID);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        
        note.productID = _productID;
        note.textOrImage = _textOrImage;
        
        emit noteInfo(_productID, _textOrImage);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External callback to notify observers after state changes
        if (noteObserver != address(0)) {
            INoteObserver(noteObserver).onNoteUpdated(_id, _productID, _textOrImage);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    function getNote(uint256 _id) view public returns (bytes32, string) {
        return (notes[_id].productID, notes[_id].textOrImage);
    }
    
    // comments section
    
    struct Comment {
        bytes3 rating; 
        string text;
    }
    
    uint public commentsLength;
    mapping (uint256 => Comment) public comments;
    address[] public commentsAccounts;
    
    event commentInfo(
        bytes3 rating,
        string text
    );
    
    function addComment(bytes3 _rating, string _text) public returns (uint) {
        Comment storage comment = comments[commentsLength];
        
        comment.rating = _rating;
        comment.text = _text;
        
        emit commentInfo(_rating, _text);
        
        commentsLength++;
        return commentsLength;
    }
        
    function setComment(uint256 _id, bytes3 _rating, string _text) public {
        Comment storage comment = comments[_id];
        
        comment.rating = _rating;
        comment.text = _text;
        
        emit commentInfo(_rating, _text);
    }
    
    function getComment(uint256 _id) view public returns (bytes3, string) {
        return (comments[_id].rating, comments[_id].text);
    }
    
}
