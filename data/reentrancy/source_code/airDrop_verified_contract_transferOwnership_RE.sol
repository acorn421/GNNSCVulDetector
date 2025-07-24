/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Added an external call to the _newOwner address before setting the newOwner state variable. This creates a stateful, multi-transaction reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit effectively:
 *    - Transaction 1: Attacker calls transferOwnership with a malicious contract address
 *    - Transaction 2+: During the external call, the malicious contract can reenter and call transferOwnership again with a different address, potentially hijacking the ownership transfer
 * 
 * 2. **State Persistence**: The vulnerability leverages the persistent state of the ownership transfer process. The owner state remains unchanged during the external call, allowing reentrancy to manipulate the transfer sequence.
 * 
 * 3. **Exploitation Scenario**:
 *    - Attacker deploys a malicious contract that implements onOwnershipTransfer
 *    - Current owner calls transferOwnership(maliciousContract)
 *    - During the external call, maliciousContract reenters and calls transferOwnership(attackerAddress)
 *    - The second call passes the onlyOwner check (since owner hasn't changed yet)
 *    - The attacker can now control who becomes the newOwner
 * 
 * 4. **Why Multiple Transactions Are Required**: The vulnerability cannot be exploited in a single transaction because:
 *    - The initial transferOwnership call must complete to set up the vulnerable state
 *    - The reentrancy occurs during the external call, creating a sequence of operations
 *    - The attacker needs to have previously deployed the malicious contract
 *    - The final acceptOwnership call (in the original contract design) would be a separate transaction
 * 
 * This creates a realistic vulnerability pattern where the external call for "notification" purposes opens up a reentrancy window that can be exploited across multiple transactions to manipulate the ownership transfer process.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the new owner about the pending transfer
        if(_newOwner.call(bytes4(keccak256("onOwnershipTransfer(address)")), owner)) {
            newOwner = _newOwner;
        } else {
            revert("Failed to notify new owner");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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