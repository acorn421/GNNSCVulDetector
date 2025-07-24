/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the new owner before updating the newOwner state variable. This creates a reentrancy window where:
 * 
 * 1. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit effectively:
 *    - Transaction 1: Initial call to transferOwnership() triggers external call
 *    - During external call: Malicious contract can reenter and call transferOwnership() again
 *    - Transaction 2: Malicious contract calls acceptOwnership() to complete unauthorized transfer
 * 
 * 2. **State Persistence**: The vulnerability leverages the persistent newOwner state between transactions:
 *    - The newOwner variable persists between the transferOwnership() and acceptOwnership() calls
 *    - During reentrancy, the malicious contract can manipulate this persistent state
 *    - Multiple reentrancy calls can overwrite the newOwner state in a controlled sequence
 * 
 * 3. **Exploitation Scenario**:
 *    - Attacker deploys malicious contract with onOwnershipTransferInitiated() function
 *    - Legitimate owner calls transferOwnership(attackerContract)
 *    - During external call, attacker's contract reenters transferOwnership() with different address
 *    - The persistent newOwner state allows the attacker to control the final ownership transfer
 *    - Attacker can then call acceptOwnership() in subsequent transaction to complete unauthorized transfer
 * 
 * 4. **Why Multi-Transaction is Required**:
 *    - The ownership transfer process inherently requires multiple transactions (transferOwnership + acceptOwnership)
 *    - The reentrancy exploits the gap between these transactions where newOwner is set but ownership hasn't transferred
 *    - The persistent state between transactions enables manipulation across multiple calls
 *    - Single transaction exploitation is limited because the actual ownership transfer occurs in acceptOwnership()
 * 
 * The vulnerability maintains the original function's intended behavior while creating a realistic security flaw that mirrors real-world reentrancy patterns seen in ownership transfer mechanisms.
 */
pragma solidity ^0.4.15;

contract Owned {
    address public owner;
    address public newOwner;

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        assert(msg.sender == owner);
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != owner);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify new owner before state update
        // This creates a reentrancy window where ownership transfer can be manipulated
        if (extcodesize(_newOwner) > 0) {
            // inline assembly to get extcodesize (Solidity 0.4.x doesn't support code.length)
            // extcodesize helper implemented below
            // call external function as originally intended
            (/*bool success*/, ) = _newOwner.call(abi.encodeWithSignature("onOwnershipTransferInitiated(address,address)", owner, _newOwner));
            // Continue regardless of success to maintain functionality
        }
        
        // State update occurs after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        newOwner = _newOwner;
    }
    
    // Helper function for extcodesize (since address.code doesn't exist in <=0.7)
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner);
        OwnerUpdate(owner, newOwner);
        owner = newOwner;
        newOwner = 0x0;
    }

    event OwnerUpdate(address _prevOwner, address _newOwner);
}

contract IERC20Token {
  function totalSupply() public constant returns (uint256) {}
  function balanceOf(address _owner) public constant returns (uint256) {}
  function transfer(address _to, uint256 _value) public returns (bool) {}
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {}
  function approve(address _spender, uint256 _value) public returns (bool) {}
  function allowance(address _owner, address _spender) public constant returns (uint256) {}

  event Transfer(address indexed _from, address indexed _to, uint256 _value);
  event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}


contract VestingContract is Owned {
    
    address public withdrawalAddress;
    address public tokenAddress;
    
    uint public lastBlockClaimed;
    uint public blockDelay;
    uint public reward;
    
    event ClaimExecuted(uint _amount, uint _blockNumber, address _destination);
    
    function VestingContract() public {
        
        lastBlockClaimed = 4315256;
        blockDelay = 5082;
        reward = 5000000000000000000000;
        
        tokenAddress = 0x2C974B2d0BA1716E644c1FC59982a89DDD2fF724;
    }
    
    function claimReward() public onlyOwner {
        require(block.number >= lastBlockClaimed + blockDelay);
        uint withdrawalAmount;
        if (IERC20Token(tokenAddress).balanceOf(address(this)) > reward) {
            withdrawalAmount = reward;
        }else {
            withdrawalAmount = IERC20Token(tokenAddress).balanceOf(address(this));
        }
        IERC20Token(tokenAddress).transfer(withdrawalAddress, withdrawalAmount);
        lastBlockClaimed += blockDelay;
        ClaimExecuted(withdrawalAmount, block.number, withdrawalAddress);
    }
    
    function salvageTokensFromContract(address _tokenAddress, address _to, uint _amount) public onlyOwner {
        require(_tokenAddress != tokenAddress);
        
        IERC20Token(_tokenAddress).transfer(_to, _amount);
    }
    
    //
    // Setters
    //

    function setWithdrawalAddress(address _newAddress) public onlyOwner {
        withdrawalAddress = _newAddress;
    }
    
    function setBlockDelay(uint _newBlockDelay) public onlyOwner {
        blockDelay = _newBlockDelay;
    }
    
    //
    // Getters
    //
    
    function getTokenBalance() public constant returns(uint) {
        return IERC20Token(tokenAddress).balanceOf(address(this));
    }
}
