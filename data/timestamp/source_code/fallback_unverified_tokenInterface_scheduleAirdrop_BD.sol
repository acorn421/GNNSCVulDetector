/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleAirdrop
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where scheduled airdrops rely on block.timestamp (now) for execution timing. The vulnerability is stateful and multi-transaction: 1) First transaction calls scheduleAirdrop() to create a scheduled drop with a future timestamp, 2) Second transaction calls executeScheduledDrop() which depends on block.timestamp comparison. Miners can manipulate timestamps within certain bounds to either delay or accelerate the execution of scheduled drops, potentially allowing them to front-run or manipulate the timing of token distributions for profit.
 */
pragma solidity ^0.4.21;

contract tokenInterface{
    uint256 public totalSupply;
    uint8 public decimals;
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
}


contract Owned{
    address public owner;
    address public newOwner;

    event OwnerUpdate(address _prevOwner, address _newOwner);

    /**
        @dev constructor
    */
    function Owned() public{
        owner = msg.sender;
    }

    // allows execution by the owner only
    modifier onlyOwner {
        assert(msg.sender == owner);
        _;
    }

    /**
        @dev allows transferring the contract ownership
        the new owner still need to accept the transfer
        can only be called by the contract owner

        @param _newOwner    new contract owner
    */
    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != owner);
        newOwner = _newOwner;
    }

    /**
        @dev used by a new owner to accept an ownership transfer
    */
    function acceptOwnership() public {
        require(msg.sender == newOwner);
        emit OwnerUpdate(owner, newOwner);
        owner = newOwner;
        newOwner = 0x0;
    }
    
    event Pause();
    event Unpause();
    bool public paused = true;
  /**
   * @dev Modifier to make a function callable only when the contract is not paused.
   */
    modifier whenNotPaused() {
        require(!paused);
        _;
    }
  /**
   * @dev Modifier to make a function callable only when the contract is paused.
   */
    modifier whenPaused() {
        require(paused);
        _;
    }
  /**
   * @dev called by the owner to pause, triggers stopped state
   */
    function pause() onlyOwner whenNotPaused public {
        paused = true;
        emit Pause();
    }
  /**
   * @dev called by the owner to unpause, returns to normal state
   */
    function unpause() onlyOwner whenPaused public {
        paused = false;
        emit Unpause();
    }
}

// a ledger recording policy participants
// kill() property is limited to the officially-released policies, which must be removed in the later template versions.
contract airDrop is Owned {
    
    tokenInterface private tokenLedger;
    
    struct ScheduledDrop {
        address[] recipients;
        uint256 value;
        uint256 scheduledTime;
        bool executed;
    }
    
    mapping(uint256 => ScheduledDrop) public scheduledDrops;
    uint256 public nextDropId = 1;
    
    //after the withdrawal, policy will transfer back the token to the ex-holder,
    //the policy balance ledger will be updated either
    function withdrawAirDrop(address[] lucky, uint256 value) onlyOwner whenNotPaused public returns (bool success) {

        uint i;

        for (i=0;i<lucky.length;i++){
            //if(!tokenLedger.transfer(lucky[i],value)){revert();}
            if(!tokenLedger.transferFrom(msg.sender,lucky[i],value)){revert();}
        }

        return true;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    
    function scheduleAirdrop(address[] recipients, uint256 value, uint256 delayInSeconds) onlyOwner whenNotPaused public returns (uint256 dropId) {
        require(recipients.length > 0, "Recipients array cannot be empty");
        require(value > 0, "Value must be greater than 0");
        require(delayInSeconds > 0, "Delay must be greater than 0");
        
        uint256 scheduledTime = now + delayInSeconds;
        
        scheduledDrops[nextDropId] = ScheduledDrop({
            recipients: recipients,
            value: value,
            scheduledTime: scheduledTime,
            executed: false
        });
        
        dropId = nextDropId;
        nextDropId++;
        
        return dropId;
    }
    
    function executeScheduledDrop(uint256 dropId) onlyOwner whenNotPaused public returns (bool success) {
        require(dropId > 0 && dropId < nextDropId, "Invalid drop ID");
        
        ScheduledDrop storage drop = scheduledDrops[dropId];
        require(!drop.executed, "Drop already executed");
        require(now >= drop.scheduledTime, "Drop not ready for execution");
        
        for (uint i = 0; i < drop.recipients.length; i++) {
            if(!tokenLedger.transferFrom(msg.sender, drop.recipients[i], drop.value)) {
                revert();
            }
        }
        
        drop.executed = true;
        return true;
    }
    
    function getScheduledDrop(uint256 dropId) public view returns (address[] recipients, uint256 value, uint256 scheduledTime, bool executed) {
        require(dropId > 0 && dropId < nextDropId, "Invalid drop ID");
        
        ScheduledDrop storage drop = scheduledDrops[dropId];
        return (drop.recipients, drop.value, drop.scheduledTime, drop.executed);
    }
    // === END FALLBACK INJECTION ===

    function applyToken(address token) onlyOwner whenPaused public returns (bool success) {
        tokenLedger=tokenInterface(token);
        return true;
    }
    
    function checkToken() public view returns(address){
        return address(tokenLedger);
    }
    
    function tokenDecimals() public view returns(uint8 dec){
        return tokenLedger.decimals();
    }
    
    function tokenTotalSupply() public view returns(uint256){
        return tokenLedger.totalSupply();
    }
    
    function kill() public onlyOwner {
        selfdestruct(owner);
    }

}
