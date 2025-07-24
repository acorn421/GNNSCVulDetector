/*
 * ===== SmartInject Injection Details =====
 * Function      : meltToken
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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced `ITokenBurnCallback(target).onTokenBurn(amount)` call before the critical state modifications
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call now occurs after validation but before state changes (balanceOf and totalSupply updates)
 * 3. **Added Code Length Check**: Realistic pattern to check if target is a contract before making the callback
 * 4. **Preserved Original Function Logic**: All original functionality and requirements remain intact
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Setup):**
 * - CFO calls `meltToken(maliciousContract, 500)` where maliciousContract has 1000 tokens
 * - External call triggers `maliciousContract.onTokenBurn(500)`
 * - During this callback, the malicious contract's state shows it still has 1000 tokens (state not yet updated)
 * - Malicious contract records this call but doesn't act yet
 * 
 * **Transaction 2 (Exploitation):**
 * - CFO calls `meltToken(maliciousContract, 400)` 
 * - External call triggers `maliciousContract.onTokenBurn(400)`
 * - The malicious contract detects this is a second call and performs reentrancy
 * - During the callback, it calls `meltToken(maliciousContract, 300)` again
 * - This creates a chain: 400 burn → reentrant 300 burn → both execute with stale balance state
 * 
 * **Transaction 3+ (State Accumulation):**
 * - Subsequent calls can exploit the accumulated inconsistent state
 * - The malicious contract can track total intended burns vs actual burns
 * - State discrepancies accumulate across multiple transactions
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 1. **State Persistence**: The `balanceOf[target]` and `totalSupply` state changes persist between transactions, creating opportunities for exploitation in subsequent calls
 * 2. **Accumulated Effect**: Each reentrant call builds upon previous state modifications, requiring multiple transactions to achieve meaningful exploitation
 * 3. **Timing Windows**: The vulnerability requires the malicious contract to accumulate information across multiple calls to effectively exploit the reentrancy
 * 4. **CFO Authorization**: Since only CFO can call this function, the exploitation requires either a compromised CFO or a malicious target contract that can influence multiple sequential calls
 * 
 * **Realistic Attack Vector:**
 * A malicious token holder contract could implement `ITokenBurnCallback` and exploit this by:
 * 1. Tracking burn attempts across multiple transactions
 * 2. Performing reentrant calls when beneficial conditions are met
 * 3. Manipulating the burn process to avoid burning the intended total amount
 * 4. Using the accumulated state inconsistencies to drain more tokens than intended
 * 
 * This creates a stateful vulnerability that requires careful orchestration across multiple transactions to exploit effectively.
 */
pragma solidity ^0.4.24;

interface ITokenBurnCallback {
    function onTokenBurn(uint256 amount) external;
}

contract ERC20TokenSAC {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address public cfoOfTokenSAC;
    
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public frozenAccount;
    
    event Transfer (address indexed from, address indexed to, uint256 value);
    event Approval (address indexed owner, address indexed spender, uint256 value);
    event MintToken (address to, uint256 mintvalue);
    event MeltToken (address from, uint256 meltvalue);
    event FreezeEvent (address target, bool result);
    
    constructor (
        uint256 initialSupply,
        string memory tokenName,
        string memory tokenSymbol
        ) public {
            cfoOfTokenSAC = msg.sender;
            totalSupply = initialSupply * 10 ** uint256(decimals);
            balanceOf[msg.sender] = totalSupply;
            name = tokenName;
            symbol = tokenSymbol;
        }
    
    modifier onlycfo {
        require (msg.sender == cfoOfTokenSAC);
        _;
    }
    
    function _transfer (address _from, address _to, uint _value) internal {
        require (!frozenAccount[_from]);
        require (!frozenAccount[_to]);
        require (_to != address(0x0));
        require (balanceOf[_from] >= _value);
        require (balanceOf[_to] + _value >= balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer (_from, _to, _value);
        assert (balanceOf[_from] + balanceOf[_to] == previousBalances);
    }
    
    function transfer (address _to, uint256 _value) public returns (bool success) {
        _transfer (msg.sender, _to, _value);
        return true;
    }
    
    function transferFrom (address _from, address _to, uint256 _value) public returns (bool success) {
        require (_value <= allowance[_from][msg.sender]);
        _transfer (_from, _to, _value);
        allowance[_from][msg.sender] -= _value;
        return true;
    }
    
    function approve (address _spender, uint256 _value) public returns (bool success) {
        require (_spender != address(0x0));
        require (_value != 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval (msg.sender, _spender, _value);
        return true;
    }
    
    function appointNewcfo (address newcfo) onlycfo public returns (bool) {
        require (newcfo != cfoOfTokenSAC);
        cfoOfTokenSAC = newcfo;
        return true;
    }
    
    function mintToken (address target, uint256 amount) onlycfo public returns (bool) {
        require (target != address(0x0));
        require (amount != 0);
        balanceOf[target] += amount;
        totalSupply += amount;
        emit MintToken (target, amount);
        return true;
    }
    
    function meltToken (address target, uint256 amount) onlycfo public returns (bool) {
        require (target != address(0x0));
        require (amount <= balanceOf[target]);
        require (amount != 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call for token burn notification - VULNERABILITY INJECTION POINT
        // This allows reentrant calls before state is properly updated
        if (isContract(target)) {
            ITokenBurnCallback(target).onTokenBurn(amount);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[target] -= amount;
        totalSupply -= amount;
        emit MeltToken (target, amount);
        return true;
    }
    
    function freezeAccount (address target, bool freeze) onlycfo public returns (bool) {
        require (target != address(0x0));
        frozenAccount[target] = freeze;
        emit FreezeEvent (target, freeze);
        return true;
    }

    // Helper function equivalent to `address.code.length > 0` in 0.4.24
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
