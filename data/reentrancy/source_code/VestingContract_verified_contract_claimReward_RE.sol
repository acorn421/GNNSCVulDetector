/*
 * ===== SmartInject Injection Details =====
 * Function      : claimReward
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Callback**: Introduced `withdrawalAddress.call(bytes4(keccak256("onRewardClaim(uint256)")), withdrawalAmount)` before the token transfer, creating an additional external call that can be exploited.
 * 
 * 2. **Maintained State Update Order**: The critical state update `lastBlockClaimed += blockDelay` remains after both external calls (callback and token transfer), creating a extended reentrancy window.
 * 
 * 3. **Preserved Function Logic**: All original functionality is maintained - the function still performs reward claiming with the same business logic.
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys a malicious contract that implements `onRewardClaim(uint256)` function
 * - Attacker calls `setWithdrawalAddress()` to set `withdrawalAddress` to their malicious contract
 * - This transaction establishes the attack setup but doesn't trigger the vulnerability
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `claimReward()` as the owner
 * - During the callback to `onRewardClaim()`, the malicious contract can re-enter `claimReward()`
 * - Since `lastBlockClaimed` hasn't been updated yet, the require check passes
 * - The attacker can drain multiple rewards in a single transaction through recursive calls
 * - Each recursive call processes before the state is updated
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **Setup Phase**: The attacker needs a separate transaction to set up the malicious withdrawal address, as they need to be the owner to call both `setWithdrawalAddress()` and `claimReward()`.
 * 
 * 2. **State Persistence**: The vulnerability depends on the persistent state of `withdrawalAddress` being set to a malicious contract from a previous transaction.
 * 
 * 3. **Accumulated State**: The attack requires the `lastBlockClaimed` state to be in a specific state from previous legitimate operations, making it dependent on the contract's historical state.
 * 
 * 4. **Realistic Attack Vector**: This mirrors real-world attacks where malicious contracts are deployed first, then integrated into target contracts through governance or admin functions, followed by exploitation in subsequent transactions.
 * 
 * The vulnerability creates a realistic scenario where an attacker (who has gained owner privileges) can manipulate the withdrawal mechanism across multiple transactions to drain rewards through reentrancy, requiring both setup transactions and exploitation sequences.
 */
pragma solidity ^0.4.15;

contract Owned {
    address public owner;
    address public newOwner;

    function Owned() {
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
        OwnerUpdate(owner, newOwner);
        owner = newOwner;
        newOwner = 0x0;
    }

    event OwnerUpdate(address _prevOwner, address _newOwner);
}

contract IERC20Token {
  function totalSupply() constant returns (uint256 totalSupply);
  function balanceOf(address _owner) constant returns (uint256 balance) {}
  function transfer(address _to, uint256 _value) returns (bool success) {}
  function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {}
  function approve(address _spender, uint256 _value) returns (bool success) {}
  function allowance(address _owner, address _spender) constant returns (uint256 remaining) {}

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
    
    function VestingContract() {
        
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Added callback mechanism to withdrawal address before state update
        if (withdrawalAddress.call(bytes4(keccak256("onRewardClaim(uint256)")), withdrawalAmount)) {
            // Callback executed successfully
        }
        
        IERC20Token(tokenAddress).transfer(withdrawalAddress, withdrawalAmount);
        
        // State update moved after external interactions - creates reentrancy window
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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