/*
 * ===== SmartInject Injection Details =====
 * Function      : addNote
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based rate limiting. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. **Added State Variables**: 
 *    - `lastNoteTimestamp`: Stores the timestamp of the last note creation
 *    - `noteTimestamps`: Maps note IDs to their creation timestamps
 *    
 * 2. **Time-Based Rate Limiting**: Added a require statement that enforces a 5-minute cooldown between note additions using `block.timestamp`
 * 
 * 3. **Timestamp Storage**: Each note's creation timestamp is stored in the `noteTimestamps` mapping
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls `addNote()` successfully, setting `lastNoteTimestamp = block.timestamp`
 * 2. **Waiting Period**: Attacker waits or attempts to call `addNote()` before 5 minutes pass (fails due to require)
 * 3. **Transaction 2**: Miner manipulation occurs - a malicious miner can manipulate `block.timestamp` to be artificially advanced
 * 4. **Transaction 3**: Owner calls `addNote()` again, but due to timestamp manipulation, the rate limiting is bypassed or extended
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires state accumulation across transactions (`lastNoteTimestamp` persists)
 * - Rate limiting logic depends on time elapsed between separate function calls
 * - Miners can only manipulate timestamps between blocks, not within a single transaction
 * - The exploit involves timing attacks across multiple blocks/transactions
 * 
 * **Exploitation Impact:**
 * - Malicious miners can manipulate note creation timing
 * - Rate limiting can be bypassed or artificially extended
 * - Note ordering can be manipulated through timestamp manipulation
 * - Business logic depending on note creation timing becomes unreliable
 * 
 * This creates a realistic vulnerability where timestamp dependence enables multi-transaction exploitation through miner manipulation of block timestamps, affecting the contract's time-based access control logic.
 */
pragma solidity ^0.4.22;

contract Owned {
    address owner;
    
    function constuctor() public {
        owner = msg.sender;
    }
    
	modifier onlyOwner {
		require(msg.sender == owner);
		_;
	}
}

contract Aeromart is Owned {
    
    struct Note {
        bytes32 productID;
        string textOrImage;
    }
    
    uint public notesLength;
    mapping (uint256 => Note) public notes;
   
    event noteInfo(
        bytes32 productID,
        string textOrImage
    );
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
uint256 public lastNoteTimestamp;
    mapping(uint256 => uint256) public noteTimestamps;
    
    function addNote(bytes32 _productID, string _textOrImage) onlyOwner public returns (uint) {
        // Time-based rate limiting with vulnerable timestamp comparison
        require(block.timestamp >= lastNoteTimestamp + 300, "Must wait 5 minutes between notes");
        
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        Note storage note = notes[notesLength];
        
        note.productID = _productID;
        note.textOrImage = _textOrImage;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store timestamp for this note (vulnerable to manipulation)
        noteTimestamps[notesLength] = block.timestamp;
        
        // Update last note timestamp for rate limiting
        lastNoteTimestamp = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        emit noteInfo(_productID, _textOrImage);
        
        notesLength++;
        return notesLength;
    }
    
    function setNote(uint256 _id, bytes32 _productID, string _textOrImage) onlyOwner public {
        Note storage note = notes[_id];
        
        note.productID = _productID;
        note.textOrImage = _textOrImage;
        
        emit noteInfo(_productID, _textOrImage);
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