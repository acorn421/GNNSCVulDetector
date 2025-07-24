/*
 * ===== SmartInject Injection Details =====
 * Function      : addComment
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the user's contract before incrementing commentsLength. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call using `msg.sender.call()` to notify the user contract of comment addition
 * 2. Placed the external call AFTER comment data is stored but BEFORE `commentsLength` is incremented
 * 3. Used a callback pattern that allows user contracts to implement an `onCommentAdded` handler
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls addComment() with malicious contract as msg.sender
 * 2. **During Transaction 1**: External call triggers attacker's onCommentAdded() callback
 * 3. **Reentrant Call**: Attacker's callback immediately calls addComment() again
 * 4. **State Corruption**: Second call uses same commentsLength index, overwriting first comment
 * 5. **Transaction 2+**: Subsequent legitimate users' comments may overwrite previous ones due to corrupted state
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction exploitation would just overwrite the same comment slot
 * - True damage occurs when commentsLength becomes desynchronized over multiple transactions
 * - Each subsequent addComment() call compounds the state corruption
 * - The vulnerability manifests as persistent state inconsistency affecting future transactions
 * 
 * **State Persistence Between Transactions:**
 * - commentsLength counter becomes permanently desynchronized
 * - Comment data integrity is compromised across multiple user interactions
 * - The corruption accumulates and affects all future addComment() calls
 * 
 * This creates a realistic vulnerability where the immediate damage may seem minimal, but the corrupted state persists and affects the entire comment system's integrity over time.
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // INJECTED: External call to reward system before state finalization
        if (msg.sender.call(bytes4(keccak256("onCommentAdded(uint256,bytes3)")), commentsLength, _rating)) {
            // Call succeeded - user contract can now re-enter
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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