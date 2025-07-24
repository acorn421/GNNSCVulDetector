/*
 * ===== SmartInject Injection Details =====
 * Function      : acceptOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to a callback contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker calls transferOwnership() to set themselves as newOwner and registers a malicious callback contract
 * 2. **Transaction 2 (Initial Attack)**: Attacker calls acceptOwnership() → external callback triggered → callback contract calls back into acceptOwnership() recursively before state is updated
 * 3. **Transaction 3 (State Exploitation)**: Due to incomplete state updates from reentrancy, the attacker can exploit inconsistent ownership states
 * 
 * **Multi-Transaction Requirements:**
 * - The vulnerability requires prior state setup (setting newOwner and callback contract)
 * - The reentrancy creates persistent state inconsistencies that can be exploited in subsequent transactions
 * - The callback mechanism allows for complex multi-step attacks across different transactions
 * - State changes persist between transactions, enabling stateful exploitation
 * 
 * **Why Multiple Transactions Are Needed:**
 * - The initial setup requires separate transactions to establish the attack conditions
 * - The reentrancy creates intermediate states that persist and can be exploited later
 * - The ownership transfer mechanism involves multiple state variables that can be manipulated across transaction boundaries
 * - The callback pattern enables complex attack sequences that span multiple blocks/transactions
 * 
 * This injection assumes the contract has been modified to include an ownershipCallback state variable and IOwnershipCallback interface, which is a realistic pattern in production contracts for notifying external systems of ownership changes.
 */
pragma solidity ^0.4.15;

contract Owned {
    address public owner;
    address public newOwner;
    address public ownershipCallback; // <-- ADDED missing variable

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        assert(msg.sender == owner);
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != owner);
        newOwner = _newOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // External call to ownership callback before state updates
        if (ownershipCallback != address(0)) {
            IOwnershipCallback(ownershipCallback).onOwnershipTransfer(owner, newOwner);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        OwnerUpdate(owner, newOwner);
        owner = newOwner;
        newOwner = 0x0;
    }

    event OwnerUpdate(address _prevOwner, address _newOwner);
}

// Corrected interface declaration for 0.4.15
contract IOwnershipCallback {
    function onOwnershipTransfer(address _prevOwner, address _newOwner) public;
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
