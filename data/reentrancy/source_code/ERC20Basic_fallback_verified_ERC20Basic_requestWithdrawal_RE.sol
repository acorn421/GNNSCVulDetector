/*
 * ===== SmartInject Injection Details =====
 * Function      : requestWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * This introduces a stateful reentrancy vulnerability that requires multiple transactions to exploit. First, an attacker must call requestWithdrawal() to set up the withdrawal request state, then wait for the time delay, and finally call executeWithdrawal() which is vulnerable to reentrancy attacks. The vulnerability exists because the external token.transfer() call happens before the state variables are updated, allowing a malicious token contract to re-enter and drain funds across multiple transactions.
 */
pragma solidity ^0.4.15;

contract Owned {

    /// @dev `owner` is the only address that can call a function with this
    /// modifier
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    address public owner;

    /// @notice The Constructor assigns the message sender to be `owner`
    function Owned() {
        owner = msg.sender;
    }

    address public newOwner;

    /// @notice `owner` can step down and assign some other address to this role
    /// @param _newOwner The address of the new owner. 0x0 can be used to create
    ///  an unowned neutral vault, however that cannot be undone
    function changeOwner(address _newOwner) onlyOwner {
        newOwner = _newOwner;
    }

    function acceptOwnership() {
        if (msg.sender == newOwner) {
            owner = newOwner;
        }
    }
}

contract ERC20Basic {
    function transfer(address to, uint256 value) public returns (bool);
    function balanceOf(address who) public constant returns (uint256);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

contract Distribute is Owned {

    mapping (address => uint) public tokensOwed;
    ERC20Basic token;

    event AmountSet(address contributor, uint amount);
    event AmountSent(address contributor, uint amount);
    
    // === FALLBACK INJECTION: Reentrancy ===
    // These mappings were previously incorrectly inside the constructor.
    mapping (address => uint) public withdrawalRequests;
    mapping (address => uint) public withdrawalTimestamps;
    // === END FALLBACK INJECTION ===

    function Distribute(address _token) public {
        token = ERC20Basic(_token);
    }
    
    // === FALLBACK INJECTION: Reentrancy ===
    function requestWithdrawal(uint amount) public {
        require(tokensOwed[msg.sender] >= amount);
        require(amount > 0);
        withdrawalRequests[msg.sender] = amount;
        withdrawalTimestamps[msg.sender] = block.timestamp;
        AmountSet(msg.sender, amount);
    }
    
    function executeWithdrawal() public {
        uint amount = withdrawalRequests[msg.sender];
        require(amount > 0);
        require(block.timestamp >= withdrawalTimestamps[msg.sender] + 1 hours);
        
        // Vulnerable to reentrancy - external call before state update
        if (token.transfer(msg.sender, amount)) {
            withdrawalRequests[msg.sender] = 0;
            tokensOwed[msg.sender] -= amount;
            AmountSent(msg.sender, amount);
        }
    }
    // === END FALLBACK INJECTION ===

    function setAmount(address contributor, uint amount) public onlyOwner {
        tokensOwed[contributor] = amount;
    }

    function withdrawAllTokens() public onlyOwner {
        token.transfer(owner, token.balanceOf(address(this)));
    }

    function() public payable {
        collect();
    }

    function collect() public {
        uint amount = tokensOwed[msg.sender];
        require(amount > 0);
        tokensOwed[msg.sender] = 0;
        token.transfer(msg.sender, amount);
        AmountSent(msg.sender, amount);
    }
}
