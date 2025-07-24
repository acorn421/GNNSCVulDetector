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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to both the current owner and new owner before and after state updates. This creates a race condition where the ownership state can be manipulated across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added external call to current owner BEFORE state update**: `owner.call(abi.encodeWithSignature("onOwnershipTransfer(address)", tOwner))` - This allows the current owner to reenter and potentially manipulate state before `newOwner` is set.
 * 
 * 2. **Added external call to new owner AFTER state update**: `tOwner.call(abi.encodeWithSignature("onOwnershipProposed(address)", owner))` - This allows the new owner to reenter when `newOwner` is set but ownership hasn't been finalized.
 * 
 * 3. **Added contract existence checks**: Both calls are protected by `code.length > 0` checks to make the code more realistic and prevent failures on EOA addresses.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1** (Initial Attack Setup):
 * - Attacker contract calls `transferOwnership(attackerContract)`
 * - During the first external call to current owner, attacker reenters and calls `transferOwnership(legitimateUser)` 
 * - This overwrites `newOwner` with `legitimateUser` instead of `attackerContract`
 * - The second external call then notifies `legitimateUser` about the ownership proposal
 * 
 * **Transaction 2** (State Manipulation):
 * - Attacker monitors the blockchain and front-runs the legitimate user's `acceptOwnership()` call
 * - Attacker calls `transferOwnership(attackerContract)` again
 * - During the reentrant call, attacker manipulates related contract state or drains funds
 * - The `newOwner` is set to `attackerContract`
 * 
 * **Transaction 3** (Completion):
 * - Attacker calls `acceptOwnership()` to complete the malicious ownership transfer
 * - Or legitimate user's transaction fails due to state changes from Transaction 2
 * 
 * **Why Multi-Transaction Required:**
 * 
 * 1. **State Persistence**: The `newOwner` state variable persists between transactions, creating opportunities for race conditions
 * 2. **Timing Dependencies**: The vulnerability exploits the gap between `transferOwnership` and `acceptOwnership` calls
 * 3. **Accumulated State Changes**: Each reentrant call can modify state that affects subsequent transactions
 * 4. **Block Boundaries**: The attack requires monitoring blockchain state and timing transactions across multiple blocks
 * 
 * This vulnerability cannot be exploited in a single transaction because it requires:
 * - Setting up the initial ownership transfer state
 * - Monitoring and reacting to blockchain state changes
 * - Coordinating multiple calls that depend on persistent state modifications
 * - Exploiting the time window between ownership proposal and acceptance
 */
pragma solidity ^0.4.16;

contract GiGi  {
   
    string public name = "GiGi";
  
    string public symbol = "GG";
  
    uint8 public decimals = 18;
  
    uint256 public totalSupply;
    bool public lockAll = false;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event FrozenFunds(address target, bool frozen);
    event OwnerUpdate(address _prevOwner, address _newOwner);

    address public owner;
   
    address internal newOwner = 0x0;
    mapping(address => bool) public frozens;
    mapping(address => uint256) public balanceOf;

    function GiGi() public {
        totalSupply = 100000000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        owner = msg.sender;
    }

  
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

 
    function transferOwnership(address tOwner) onlyOwner public {
        require(owner != tOwner);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify current owner about pending transfer - vulnerable external call
        if (isContract(owner)) {
            owner.call(abi.encodeWithSignature("onOwnershipTransfer(address)", tOwner));
        }
        
        newOwner = tOwner;
        
        // Notify new owner about proposed ownership - vulnerable external call
        if (isContract(tOwner)) {
            tOwner.call(abi.encodeWithSignature("onOwnershipProposed(address)", owner));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner && newOwner != 0x0);
        owner = newOwner;
        newOwner = 0x0;
        emit OwnerUpdate(owner, newOwner);
    }

   
    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozens[target] = freeze;
        emit FrozenFunds(target, freeze);
    }

    function freezeAll(bool lock) onlyOwner public {
        lockAll = lock;
    }

    function contTransfer(address _to, uint256 weis) onlyOwner public {
        _transfer(this, _to, weis);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function _transfer(address _from, address _to, uint _value) internal {
       
        require(!lockAll);
      
        require(_to != 0x0);
    
        require(balanceOf[_from] >= _value);
   
        require(balanceOf[_to] + _value >= balanceOf[_to]);
      
        require(!frozens[_from]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    // Helper function to check if an address is a contract
    function isContract(address _addr) internal constant returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

}
