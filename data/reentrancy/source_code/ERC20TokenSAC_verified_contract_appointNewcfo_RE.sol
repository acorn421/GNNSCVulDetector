/*
 * ===== SmartInject Injection Details =====
 * Function      : appointNewcfo
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added State Variables** (assumed to be added to contract):
 *    - `address public pendingCfoChange` - Tracks pending CFO changes
 *    - `uint256 public pendingCfoTimestamp` - Timestamp of pending change
 *    - `address public governanceContract` - External governance contract address
 * 
 * 2. **Introduced External Call Before State Change**:
 *    - Added call to `IGovernance(governanceContract).notifyRoleChange()` before updating `cfoOfTokenSAC`
 *    - This creates a reentrancy window where the contract state is inconsistent
 * 
 * 3. **Added Pending State Management**:
 *    - Set `pendingCfoChange` and `pendingCfoTimestamp` before external call
 *    - This creates additional state that can be manipulated during reentrancy
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys malicious governance contract
 * - Attacker (as current CFO) calls `appointNewcfo()` with attacker's address as newcfo
 * - During `notifyRoleChange()` call, malicious contract doesn't reenter yet - just records the call
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `appointNewcfo()` again with different address
 * - During the external call to `notifyRoleChange()`, malicious governance contract now reenters
 * - The malicious contract calls `appointNewcfo()` again with attacker's preferred address
 * - This creates a sequence: pendingCfoChange is set → external call → reentrant call modifies state → original call completes
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability requires the `governanceContract` to be set up in advance (separate transaction)
 * 2. **Reentrancy Window**: The external call creates a window where `pendingCfoChange` is set but `cfoOfTokenSAC` hasn't been updated yet
 * 3. **Modifier Bypass**: The `onlycfo` modifier check passes initially, but during reentrancy, the attacker can manipulate the CFO role mid-execution
 * 4. **Sequence Dependency**: The exploit requires a specific sequence of calls to manipulate the pending state and then exploit the reentrancy window
 * 
 * **Exploitation Impact:**
 * - Attacker can bypass the `require(newcfo != cfoOfTokenSAC)` check
 * - Attacker can manipulate CFO changes in unexpected ways
 * - The pending state variables can be left in inconsistent states
 * - Multiple CFO changes can occur in a single transaction sequence, violating business logic assumptions
 */
pragma solidity ^0.4.24;

interface IGovernance {
    function notifyRoleChange(address oldCfo, address newCfo) external;
}

contract ERC20TokenSAC {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address public cfoOfTokenSAC;
    
    // State variables added for appointNewcfo
    address public governanceContract;
    address public pendingCfoChange;
    uint256 public pendingCfoTimestamp;
    
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store pending CFO change for external validation
        pendingCfoChange = newcfo;
        pendingCfoTimestamp = block.timestamp;
        
        // External call to notify governance system (VULNERABLE)
        if (governanceContract != address(0)) {
            IGovernance(governanceContract).notifyRoleChange(cfoOfTokenSAC, newcfo);
        }
        
        // State change after external call - creates reentrancy window
        cfoOfTokenSAC = newcfo;
        
        // Clear pending change
        pendingCfoChange = address(0);
        pendingCfoTimestamp = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}
