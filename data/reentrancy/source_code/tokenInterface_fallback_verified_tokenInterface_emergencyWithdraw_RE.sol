/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
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
 * This introduces a stateful multi-transaction reentrancy vulnerability. The emergencyWithdraw function makes an external call to tokenLedger.transfer() before updating the emergencyWithdrawals mapping. An attacker can exploit this by: 1) First calling enableEmergencyMode (if they become owner through other means), 2) Then calling emergencyWithdraw which triggers the external call, 3) The malicious token contract can re-enter emergencyWithdraw before the mapping is updated, allowing multiple withdrawals. The vulnerability requires multiple transactions and state persistence through the emergencyWithdrawals mapping.
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
    
    // Variables and mapping for emergency mode and withdrawals
    bool public emergencyMode = false;
    mapping(address => bool) public emergencyWithdrawals;

    // Functions for emergency mode control
    function enableEmergencyMode() public onlyOwner {
        emergencyMode = true;
    }
    
    function disableEmergencyMode() public onlyOwner {
        emergencyMode = false;
    }
    
    function emergencyWithdraw(address recipient, uint256 amount) public {
        require(emergencyMode, "Emergency mode not enabled");
        require(!emergencyWithdrawals[recipient], "Already withdrawn");
        
        // External call before state change - reentrancy vulnerability
        if(tokenLedger.transfer(recipient, amount)) {
            emergencyWithdrawals[recipient] = true;
        }
    }
    
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
