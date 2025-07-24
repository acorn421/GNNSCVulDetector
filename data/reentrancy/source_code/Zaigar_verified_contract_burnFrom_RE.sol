/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a "notification" mechanism that calls the `_from` address with `onBeforeBurn(address,uint256)` before any state variables are modified.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call occurs after the initial checks but before the critical state updates (balance, allowance, totalSupply modifications).
 * 
 * 3. **Realistic Feature Addition**: The notification mechanism appears as a legitimate feature to inform contract holders about impending burns, making it seem like a reasonable enhancement.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - User approves tokens for the attacker contract: `approve(attackerContract, 1000)`
 * - This sets `allowance[user][attackerContract] = 1000`
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `burnFrom(maliciousContract, 100)` where `maliciousContract` is controlled by the attacker
 * - The function checks pass: balance >= 100, allowance >= 100
 * - External call is made to `maliciousContract.onBeforeBurn(attacker, 100)`
 * - **Reentrancy Point**: `maliciousContract` re-enters `burnFrom` again before the original state updates complete
 * - Since state hasn't been updated yet, the checks still pass for subsequent calls
 * - Attacker can burn more tokens than they should be able to by calling `burnFrom` multiple times recursively
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **Allowance Dependency**: The vulnerability depends on pre-existing allowance state set in a previous transaction. Without prior approval, the initial checks would fail.
 * 
 * 2. **State Persistence**: The allowance value must persist from the approval transaction to the burn transaction, creating a multi-transaction attack surface.
 * 
 * 3. **Accumulated State Changes**: Each reentrant call during the burn process can consume the same allowance multiple times before it's properly decremented, but this only works because the allowance was established in a prior transaction.
 * 
 * 4. **Cannot Be Atomic**: The attack requires:
 *    - Transaction 1: Set up allowance
 *    - Transaction 2: Exploit via reentrancy during burn
 *    - The vulnerability cannot be exploited in a single transaction because the allowance must exist before the burn attempt.
 * 
 * **Exploitation Impact:**
 * - An attacker can burn more tokens than their allowance should permit
 * - Multiple burns can occur before the allowance is properly decremented
 * - The total supply can be incorrectly reduced beyond what the allowance originally permitted
 * - This creates accounting inconsistencies that persist across the blockchain state
 */
pragma solidity ^0.4.16; // Solidity version 0.4.16

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external;
}

contract Zaigar {
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function Zaigar() public {
        totalSupply = 1000000000 * 10 ** 8;
        balanceOf[msg.sender] = totalSupply;
        name = "Zaigar";
        symbol = "ZAI";
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
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
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
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Make sure _from is a contract by checking extcodesize (pre-0.8 style)
        uint codeLength = 0;
        assembly { codeLength := extcodesize(_from) }
        if (codeLength > 0) {
            _from.call(abi.encodeWithSignature("onBeforeBurn(address,uint256)", msg.sender, _value));
            // Continue even if notification fails - this is just courtesy
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        emit Burn(_from, _value);
        return true;
    }
}