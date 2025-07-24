/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that allows external contracts to be notified during the burn process. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added `burnCallbacks` mapping to store callback contract addresses for each user
 * 2. Added `burnInProgress` mapping to track burn operations in progress
 * 3. Added `setBurnCallback` function to register callback contracts (owner-only)
 * 4. Modified `burnFrom` to make external call to registered callback before updating state
 * 5. State updates (balance reduction, totalSupply decrease) happen after the external call
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1 (Setup)**: Owner calls `setBurnCallback(_victim, _maliciousContract)` to register an attacker-controlled callback contract
 * 2. **Transaction 2 (Exploit)**: Owner calls `burnFrom(_victim, amount)`, which:
 *    - Sets `burnInProgress[_victim] = true`
 *    - Calls the malicious callback contract
 *    - The callback can re-enter `burnFrom` or other functions while `burnInProgress` is true
 *    - The callback can also call other contract functions that depend on the victim's balance before it's actually reduced
 *    - State updates happen after the external call, creating a window of inconsistent state
 * 
 * **Why Multi-Transaction is Required:**
 * - The attack requires setup phase (registering callback) and exploitation phase (triggering burn)
 * - The vulnerability depends on the persistent state of `burnCallbacks` mapping set in a previous transaction
 * - The `burnInProgress` flag persists across the external call, enabling the callback to detect and exploit the intermediate state
 * - Real exploitation would involve the callback contract performing operations that depend on the victim's balance being higher than it will be after the burn completes
 * 
 * This creates a realistic scenario where an owner-controlled callback system introduces a reentrancy vulnerability that can only be exploited through multiple coordinated transactions.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => address) public burnCallbacks;
    mapping(address => bool) public burnInProgress;
    
    function setBurnCallback(address _who, address _callback) public {
        require(msg.sender == owner);
        burnCallbacks[_who] = _callback;
    }
    
    function burnFrom(address _who,uint256 _value)public returns (bool){
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        require(msg.sender == owner);
        assert(balances[_who] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Set burn in progress flag
        burnInProgress[_who] = true;
        
        // External call to notify callback contract before state updates
        if(burnCallbacks[_who] != address(0)) {
            // Call external contract - this creates reentrancy opportunity
            (bool success, ) = burnCallbacks[_who].call(
                abi.encodeWithSignature("onBurnNotification(address,uint256)", _who, _value)
            );
            // Continue regardless of callback success
        }
        
        // State updates happen after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply -= _value;
        balances[_who] -= _value;
        lockedBalances[_who][0] = 0;
        lockedBalances[_who][1] = 0;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear burn in progress flag
        burnInProgress[_who] = false;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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