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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This vulnerability creates a stateful, multi-transaction reentrancy attack. The vulnerability requires: 1) First transaction: User calls requestWithdrawal() to initiate withdrawal request and lock funds. 2) Wait 24 hours for withdrawal to become available. 3) Second transaction: User calls executeWithdrawal() which is vulnerable to reentrancy because the state variables (withdrawalPending, balances, withdrawalRequests) are updated AFTER the external call to msg.sender. An attacker can create a malicious contract that recursively calls executeWithdrawal() during the fallback function, draining more funds than they should be able to access. The vulnerability is stateful because it requires the withdrawal request state to persist between transactions and the 24-hour delay ensures multiple transactions are needed.
 */
pragma solidity ^0.4.23;

contract USDT {
    mapping (address => uint256) private balances;
    mapping (address => uint256[2]) private lockedBalances;
    string public name = "USDT";                   //fancy name: eg Simon Bucks
    uint8 public decimals = 6;                //How many decimals to show.
    string public symbol = "USDT";                 //An identifier: eg SBX
    uint256 public totalSupply = 1000000000000000;
    address public owner;
    event Transfer(address indexed _from, address indexed _to, uint256 _value); 

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) withdrawalRequests;
    mapping(address => uint256) withdrawalTimestamps;
    mapping(address => bool) withdrawalPending;
    
    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol,
        address _owner
    ) public {
        balances[_owner] = _initialAmount;                   // Give the owner all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
        owner = _owner;                                      // set owner
    }

    function requestWithdrawal(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        require(!withdrawalPending[msg.sender], "Withdrawal already pending");
        
        withdrawalRequests[msg.sender] = _amount;
        withdrawalTimestamps[msg.sender] = now + 24 hours; // 24 hour delay
        withdrawalPending[msg.sender] = true;
        
        balances[msg.sender] -= _amount;
        balances[address(this)] += _amount;
    }
    
    function executeWithdrawal() public {
        require(withdrawalPending[msg.sender], "No withdrawal pending");
        require(now >= withdrawalTimestamps[msg.sender], "Withdrawal not yet available");
        
        uint256 amount = withdrawalRequests[msg.sender];
        require(balances[address(this)] >= amount, "Insufficient contract balance");
        
        withdrawalPending[msg.sender] = false;
        
        // Vulnerable to reentrancy - state not updated before external call
        msg.sender.call.value(amount)("");
        
        balances[address(this)] -= amount;
        withdrawalRequests[msg.sender] = 0;
        withdrawalTimestamps[msg.sender] = 0;
    }
    // === END FALLBACK INJECTION ===

    /*DirectDrop and AirDrop*/
    /*Checking lock limit and time limit while transfering.*/
    function transfer(address _to, uint256 _value) public returns (bool success) {
        //Before ICO finish, only own could transfer.
        if(_to != address(0)){
            if(lockedBalances[msg.sender][1] >= now) {
                require((balances[msg.sender] > lockedBalances[msg.sender][0]) &&
                 (balances[msg.sender] - lockedBalances[msg.sender][0] >= _value));
            } else {
                require(balances[msg.sender] >= _value);
            }
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            emit Transfer(msg.sender, _to, _value);
            return true;
        }
    }
    /*With permission, destory token from an address and minus total amount.*/
    function burnFrom(address _who,uint256 _value)public returns (bool){
        require(msg.sender == owner);
        assert(balances[_who] >= _value);
        totalSupply -= _value;
        balances[_who] -= _value;
        lockedBalances[_who][0] = 0;
        lockedBalances[_who][1] = 0;
        return true;
    }
    /*With permission, creating coin.*/
    function makeCoin(uint256 _value)public returns (bool){
        require(msg.sender == owner);
        totalSupply += _value;
        balances[owner] += _value;
        return true;
    }
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
    /*With permission, withdraw ETH to owner address from smart contract.*/
    function withdraw() public{
        require(msg.sender == owner);
        msg.sender.transfer(address(this).balance);
    }
    /*With permission, withdraw ETH to an address from smart contract.*/
    function withdrawTo(address _to) public{
        require(msg.sender == owner);
        address(_to).transfer(address(this).balance);
    }
}
