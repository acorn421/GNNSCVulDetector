/*
 * ===== SmartInject Injection Details =====
 * Function      : addComment
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability that requires multiple comment submissions to exploit. The vulnerability has three key components:
 * 
 * 1. **Time-based Comment Restrictions**: Added a 5-minute cooldown period between comments using block.timestamp comparison with the previous comment's stored timestamp. This creates state dependency where each comment's timestamp affects future comment validity.
 * 
 * 2. **Rating Manipulation Window**: Implemented a 1-hour window where comments receive a rating boost if submitted within this timeframe of the previous comment. This creates a multi-transaction attack vector where attackers can manipulate timing to boost ratings.
 * 
 * 3. **Persistent Timestamp State**: Each comment now stores its block.timestamp, creating accumulated state that affects future function calls.
 * 
 * **Multi-Transaction Exploitation Scenarios:**
 * 
 * 1. **Miner Timestamp Manipulation**: Miners can manipulate block.timestamp across multiple blocks to bypass the 5-minute cooldown or extend/shrink the 1-hour rating boost window.
 * 
 * 2. **Coordinated Timing Attacks**: Attackers can submit multiple comments with precisely timed intervals, manipulating the timestamp comparisons to achieve desired rating boosts or bypass restrictions.
 * 
 * 3. **State Accumulation Attack**: The vulnerability requires building up comment state over multiple transactions, where each comment's timestamp becomes part of the exploitable state for future comments.
 * 
 * The vulnerability is realistic because adding timestamps to comments is a common feature, and using block.timestamp for business logic appears natural but creates the security flaw. The multi-transaction nature is essential because the vulnerability relies on the relationship between timestamps across different comment submissions.
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
        uint256 timestamp; // <-- Added timestamp field
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
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Timestamp-based comment validation using accumulated state
        if (commentsLength > 0) {
            Comment storage lastComment = comments[commentsLength - 1];
            // Critical vulnerability: Using block.timestamp for business logic
            // allowing time-based manipulation across multiple transactions
            require(block.timestamp - lastComment.timestamp >= 300, "Comment too soon");
            
            // Additional vulnerability: timestamp-based rating boost
            if (block.timestamp - lastComment.timestamp < 3600) {
                // Boost rating if commenting within 1 hour of last comment
                comment.rating = bytes3(uint24(comment.rating) + 1);
            }
        }
        
        // Store timestamp for future state-dependent operations
        comment.timestamp = block.timestamp;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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