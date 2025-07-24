/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: Inserted a call to recipient's `onTokenReceived` function before updating the allowance state, violating the Checks-Effects-Interactions (CEI) pattern.
 * 
 * 2. **State Update After External Call**: The allowance reduction (`allowance[_from][msg.sender] -= _value`) now occurs AFTER the external call, creating a reentrancy window.
 * 
 * 3. **Multi-Transaction Exploitation Vector**: 
 *    - **Transaction 1**: Attacker calls `transferFrom` with a malicious contract as `_to`
 *    - **During external call**: Malicious contract re-enters `transferFrom` with the same allowance (not yet decremented)
 *    - **Transaction 2+**: Attacker can continue exploiting across multiple transactions by setting up state that enables repeated reentrancy
 * 
 * 4. **Stateful Nature**: The vulnerability depends on:
 *    - Allowance state persisting between transactions
 *    - Each successful reentrancy drains more allowance than intended
 *    - Multiple transactions needed to fully exploit accumulated allowance drainage
 *    - The attack requires the attacker to first gain allowance approval, then exploit it across multiple calls
 * 
 * 5. **Why Multi-Transaction**: 
 *    - The attacker needs separate transactions to set up allowances first
 *    - Each reentrancy call can only exploit the current allowance state
 *    - Maximum damage requires multiple coordinated transactions to drain different allowances
 *    - The vulnerability accumulates effect across transaction boundaries through persistent state manipulation
 * 
 * This creates a realistic vulnerability pattern where the attacker must orchestrate multiple transactions to fully exploit the allowance system through reentrancy.
 */
pragma solidity ^0.4.20;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract AdrenalinCoin {
    string public name = "AdrenalinCoin";
    string public symbol = "ADR";
    uint8 public decimals = 6;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = 20000000000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = 20000000000000;                // Give the creator all initial tokens
        name = "AdrenalinCoin";                                   // Set the name for display purposes
        symbol = "ADR";                               // Set the symbol for display purposes
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient before state update - potential for reentrancy
        if (isContract(_to)) {
            // Note: .call should use abi.encodeWithSignature in Solidity 0.4.x is not available; use bytes4 selector below
            // We'll use the lowest-level call as a placeholder for ABI-encoding
            // This is for demonstration purpose and potential static analyzer only; actual call code strictly preserved in spirit
            if (!_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
                revert("Recipient notification failed");
            }
        }
        // State update occurs AFTER external call - CEI pattern violation
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
    
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
