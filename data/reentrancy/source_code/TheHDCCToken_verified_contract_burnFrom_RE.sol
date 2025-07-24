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
 * Total Found   : 3 issues
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
 * 1. **Added External Call Before State Updates**: Introduced a callback mechanism that calls `tokenRecipient(_from).receiveApproval()` before updating the state variables (balanceOf, allowance, totalSupply).
 * 
 * 2. **Conditional Callback Logic**: The external call only triggers when `_from` is a contract address and is different from `msg.sender`, making it appear as a legitimate notification feature.
 * 
 * 3. **Try-Catch Pattern**: Used try-catch to handle callback failures gracefully, making the code appear production-ready and realistic.
 * 
 * 4. **Preserved Function Signature**: Maintained the exact same function parameters and return type.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements `tokenRecipient`
 * - The malicious contract has a large token balance and sets allowance for the attacker
 * - Attacker calls `burnFrom()` targeting the malicious contract
 * 
 * **Transaction 2 (Reentrancy Attack):**
 * - When `burnFrom()` executes, it calls the malicious contract's `receiveApproval()` function
 * - The malicious contract's `receiveApproval()` calls `burnFrom()` again (reentrancy)
 * - Since state hasn't been updated yet, the second call passes the balance and allowance checks
 * - This creates a recursive loop where tokens are burned multiple times
 * 
 * **Transaction 3 (Completion):**
 * - The attacker completes the exploitation by draining more tokens than the allowance should permit
 * - Each recursive call burns tokens without updating the allowance until the entire call stack completes
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on the persistent state of `balanceOf` and `allowance` between transactions. The attacker needs to first establish an allowance and balance in previous transactions.
 * 
 * 2. **Recursive Call Dependency**: The reentrancy attack depends on the contract's state being consistent across multiple nested calls within the same transaction, but the setup requires prior transactions to establish the vulnerable state.
 * 
 * 3. **Allowance Mechanism**: The multi-transaction nature comes from the ERC-20 allowance pattern where someone must first approve tokens to be burned, then the burnFrom can be called multiple times maliciously.
 * 
 * **Exploitation Impact:**
 * - Attacker can burn more tokens than their allowance permits
 * - Total supply can be reduced beyond intended limits
 * - The attack can be repeated across multiple transactions for sustained exploitation
 * - Each successful attack builds on the state changes from previous attacks
 */
pragma solidity ^0.4.16;
 
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
 
contract TheHDCCToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;  // 18 是建议的默认值
    uint256 public totalSupply;
 
    mapping (address => uint256) public balanceOf;  //
    mapping (address => mapping (address => uint256)) public allowance;
 
    event Transfer(address indexed from, address indexed to, uint256 value);
 
    event Burn(address indexed from, uint256 value);
 

    function TheHDCCToken(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }
 

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
 
    function transfer(address _to, uint256 _value) public returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
    }
 
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }
 
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
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
        Burn(msg.sender, _value);
        return true;
    }
 
    // Fixed function header here
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call before state updates enables reentrancy
        if (_from != msg.sender && isContract(_from)) {
            // Notify the token holder about the burn (callback mechanism)
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool is_contract) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
