/*
 * ===== SmartInject Injection Details =====
 * Function      : setComment
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
 * Injected a timestamp dependence vulnerability by introducing time-based comment editing restrictions and rating decay calculations that rely on block.timestamp. The vulnerability requires multiple transactions: (1) initial comment creation with timestamp storage, (2) later setComment calls that check elapsed time using block.timestamp for critical business logic decisions. This creates a stateful vulnerability where miners can manipulate timestamps to bypass time restrictions or affect rating calculations across multiple blocks. The vulnerability is realistic as it implements common time-based access controls found in real applications, but the dependence on manipulable block.timestamp makes it exploitable through miner timestamp manipulation over multiple transactions.
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
        uint256 timestamp;
        uint256 lastModified;
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
        comment.timestamp = block.timestamp;
        comment.lastModified = block.timestamp;
        
        emit commentInfo(_rating, _text);
        
        commentsLength++;
        return commentsLength;
    }
        
    function setComment(uint256 _id, bytes3 _rating, string _text) public {
        Comment storage comment = comments[_id];
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based editing restriction: only allow editing within 24 hours
        require(comment.timestamp > 0, "Comment does not exist");
        
        uint256 timeSinceCreation = block.timestamp - comment.timestamp;
        bool canEdit = timeSinceCreation <= 86400; // 24 hours in seconds
        
        if (!canEdit) {
            // After 24 hours, apply time-based rating decay
            // The longer the comment exists, the more the rating is reduced
            uint256 daysPassed = timeSinceCreation / 86400;
            uint256 ratingDecay = daysPassed * 10; // 10 points per day
            
            // Convert bytes3 rating to uint for calculation
            uint256 originalRating = uint256(_rating);
            uint256 adjustedRating = originalRating > ratingDecay ? originalRating - ratingDecay : 0;
            
            comment.rating = bytes3(adjustedRating);
        } else {
            comment.rating = _rating;
        }
        
        comment.text = _text;
        comment.lastModified = block.timestamp;
        
        emit commentInfo(comment.rating, _text);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    function getComment(uint256 _id) view public returns (bytes3, string) {
        return (comments[_id].rating, comments[_id].text);
    }
    
}