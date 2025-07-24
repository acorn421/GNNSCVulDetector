/*
 * ===== SmartInject Injection Details =====
 * Function      : acceptOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the newOwner contract before updating the state variables. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * 1. **Transaction 1 (Setup)**: Attacker calls `transferOwnership()` to set themselves as `newOwner`
 * 2. **Transaction 2 (Exploitation)**: Attacker calls `acceptOwnership()` which:
 *    - Passes the `require(msg.sender == newOwner)` check
 *    - Emits the `OwnerUpdate` event
 *    - Makes external call to attacker's `onOwnershipAccepted()` callback
 *    - **Critical Window**: State variables `owner` and `newOwner` are NOT yet updated
 * 3. **Transaction 3 (Re-entry)**: Inside the callback, attacker can:
 *    - Call `acceptOwnership()` again (still passes require check since `newOwner` unchanged)
 *    - Or call other functions that depend on the current ownership state
 *    - Manipulate contract state while ownership is in an inconsistent state
 * 
 * **Why Multi-Transaction Required:**
 * - **State Persistence**: The `newOwner` state persists between transactions, allowing the attacker to maintain their position through multiple calls
 * - **Accumulated State Changes**: The vulnerability exploits the window between authorization check and state update across multiple function calls
 * - **Cross-Transaction Dependencies**: The exploit depends on the state set up in previous transactions (transferOwnership) and leverages the persistent state during the reentrancy window
 * 
 * **Exploitation Impact:**
 * - Attacker can potentially call ownership-dependent functions while the contract is in an inconsistent state
 * - Could lead to unauthorized access to `onlyOwner` functions during the reentrancy window
 * - State corruption through repeated ownership acceptance calls
 * 
 * This is a realistic vulnerability as the callback mechanism appears to be a legitimate feature for notifying new owners about ownership changes.
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
    constructor() public{
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the new owner through external call before state update
        // This creates a reentrancy window for multi-transaction exploitation
        if (newOwner != address(0)) {
            // Check if newOwner is a contract and has the callback function
            uint256 size;
            address _newOwner = newOwner;
            assembly { size := extcodesize(_newOwner) }
            if (size > 0) {
                // Call the onOwnershipAccepted callback on the new owner contract
                // This external call happens before state variables are updated
                newOwner.call(abi.encodeWithSignature("onOwnershipAccepted()"));
                // Continue execution regardless of callback result
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        owner = newOwner;
        newOwner = address(0);
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
