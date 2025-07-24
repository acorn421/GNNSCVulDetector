/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address after balance updates but before the Transfer event emission. This creates a classic reentrancy pattern where:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using low-level call() function
 * 2. The call invokes `onTokenReceived(address,uint256)` on the recipient contract
 * 3. Added require statement to ensure the external call succeeds
 * 4. External call occurs AFTER balance state changes but BEFORE event emission
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * - **Transaction 1**: Victim calls transfer() to malicious contract, triggering the external call
 * - **Transaction 2**: Malicious contract's onTokenReceived() callback re-enters transfer() while state is in intermediate state
 * - **Transaction 3+**: Additional reentrancy calls can continue exploiting the accumulated state inconsistencies
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Accumulation**: The vulnerability exploits the persistent balance state changes that accumulate across multiple reentrant calls
 * 2. **Callback Dependency**: The external call creates a dependency on the recipient contract's response, which enables multi-transaction exploitation
 * 3. **Event Ordering**: The Transfer event occurs after the external call, allowing state manipulation before event emission
 * 4. **Persistent State Corruption**: Each reentrant call can further corrupt the balance state, requiring multiple transactions to fully exploit
 * 
 * **Exploitation Scenario:**
 * A malicious contract can implement onTokenReceived() to immediately call transfer() again, creating a chain of reentrant calls that can drain funds by exploiting the temporary state inconsistency where balances have been updated but the transaction hasn't completed. The vulnerability requires multiple function calls because the attacker needs to build up state corruption through repeated reentrancy.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about the transfer - introduces reentrancy vulnerability
        if (isContract(_to)) {
            // workaround for lack of abi.encodeWithSignature in <0.5.0, use bytes4 signature and abi-encoding manually
            bytes4 selector = bytes4(keccak256("onTokenReceived(address,uint256)"));
            // In 0.4.x: must use low-level call (limited abi.encode)
            // So just use call with manually packed signature and arguments
            bool callSuccess = _to.call(
                selector,
                msg.sender,
                _value
            );
            require(callSuccess);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        totalSupply -= _value;
        balances[_who] -= _value;
        return true;
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
    // Utility: Detect if address is contract (in Solidity <0.5.0)
    function isContract(address _addr) private view returns (bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
    

}
