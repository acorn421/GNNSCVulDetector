/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleNoteUpdate
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability where the contract relies on 'now' (block.timestamp) for scheduling and executing updates. The vulnerability is stateful and multi-transaction: 1) First transaction calls scheduleNoteUpdate() to schedule an update with a specific executeTime based on 'now' 2) Second transaction calls executeScheduledUpdate() which checks if 'now >= executeTime' 3) Miners can manipulate block timestamps within reasonable bounds to either delay or accelerate execution 4) The scheduled state persists between transactions and accumulates multiple scheduled updates 5) This creates a multi-step attack vector where timestamp manipulation affects the timing of critical note updates
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // New state variables for scheduled updates
    struct ScheduledUpdate {
        uint256 noteId;
        bytes32 productID;
        string textOrImage;
        uint256 executeTime;
        bool executed;
    }
    
    uint public scheduledUpdatesLength;
    mapping (uint256 => ScheduledUpdate) public scheduledUpdates;
    
    event UpdateScheduled(uint256 scheduleId, uint256 noteId, uint256 executeTime);
    event UpdateExecuted(uint256 scheduleId, uint256 noteId);
    
    function scheduleNoteUpdate(uint256 _noteId, bytes32 _productID, string _textOrImage, uint256 _delay) onlyOwner public returns (uint256) {
        ScheduledUpdate storage update = scheduledUpdates[scheduledUpdatesLength];
        
        update.noteId = _noteId;
        update.productID = _productID;
        update.textOrImage = _textOrImage;
        update.executeTime = now + _delay;
        update.executed = false;
        
        emit UpdateScheduled(scheduledUpdatesLength, _noteId, update.executeTime);
        
        scheduledUpdatesLength++;
        return scheduledUpdatesLength - 1;
    }
    
    function executeScheduledUpdate(uint256 _scheduleId) public {
        ScheduledUpdate storage update = scheduledUpdates[_scheduleId];
        
        require(!update.executed);
        require(now >= update.executeTime);
        
        Note storage note = notes[update.noteId];
        note.productID = update.productID;
        note.textOrImage = update.textOrImage;
        
        update.executed = true;
        
        emit UpdateExecuted(_scheduleId, update.noteId);
        emit noteInfo(update.productID, update.textOrImage);
    }
    // === END FALLBACK INJECTION ===

    
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
