/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added a callback mechanism that calls `onTokenBurn(uint256)` on the target address if it's a contract
 * 2. The external call occurs AFTER the balance check but BEFORE the critical state updates (totalSupply and balances)
 * 3. This violates the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract and gets tokens allocated to it
 * 2. **Transaction 2**: Origin address calls `burnFrom` on the malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenBurn` callback is triggered, allowing it to re-enter `burnFrom` or other functions before the original burn completes
 * 4. **State Manipulation**: The malicious contract can call other functions (like `transfer` or `transferBack`) during the callback, exploiting the fact that its balance hasn't been reduced yet
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker needs separate transactions to set up the malicious contract and fund it
 * - The vulnerability depends on the accumulated state (token balance) from previous transactions
 * - The exploit requires the originAddress to initiate the burn, creating a multi-party, multi-transaction scenario
 * - The reentrancy can only be effective if there's pre-existing state to manipulate
 * 
 * **Realistic Integration:**
 * The callback mechanism appears as a legitimate feature to notify contracts about token burns, making it a subtle but dangerous addition that could realistically appear in production code.
 */
pragma solidity ^0.4.18;

contract DBC {
    mapping (address => uint256) private balances;
    string public name;                   //fancy name: eg Simon Bucks
    uint8 public decimals;                //How many decimals to show.
    string public symbol;                 //An identifier: eg SBX
    uint256 public totalSupply;
    address private originAddress;
    bool private locked;
    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    function DBC(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;               // Give the creator all initial tokens
        totalSupply = _initialAmount;                        // Update total supply
        name = _tokenName;                                   // Set the name for display purposes
        decimals = _decimalUnits;                            // Amount of decimals for display purposes
        symbol = _tokenSymbol;                               // Set the symbol for display purposes
        originAddress = msg.sender;
        locked = false;
    }
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(!locked);
        require(_to != address(0));
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    function setLock(bool _locked)public returns (bool){
        require(msg.sender == originAddress);
        locked = _locked;
        return true;
    }
    function burnFrom(address _who,uint256 _value)public returns (bool){
        require(msg.sender == originAddress);
        assert(balances[_who] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the address being burned about the pending burn
        // This creates a callback opportunity before state changes
        if(_who != address(0) && isContract(_who)) {
            // Call to external contract - potential reentrancy point
            _who.call(abi.encodeWithSignature("onTokenBurn(uint256)", _value));
            // Continue execution regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply -= _value;
        balances[_who] -= _value;
        return true;
    }
    // Helper to check if target is a contract (compatible with Solidity 0.4.x)
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
    function makeCoin(uint256 _value)public returns (bool){
        require(msg.sender == originAddress);
        totalSupply += _value;
        balances[originAddress] += _value;
        return true;
    }
    function transferBack(address _who,uint256 _value)public returns (bool){
        require(msg.sender == originAddress);
        assert(balances[_who] >= _value);
        balances[_who] -= _value;
        balances[originAddress] += _value;
        return true;
    }
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
    

}