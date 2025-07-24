/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target address after state updates but before function completion. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to target.call() with onTokenMinted callback after state updates
 * 2. State modifications (balanceOf[target] and totalSupply) occur before the external call
 * 3. The external call allows the target contract to re-enter mintToken during the callback
 * 4. Added initial state tracking variables for context
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Setup Phase**: Attacker deploys a malicious contract that implements onTokenMinted callback
 * 2. **First Transaction**: CFO calls mintToken with malicious contract as target
 * 3. **Reentrancy Phase**: During the external call, malicious contract re-enters mintToken
 * 4. **State Accumulation**: Each re-entrant call adds more tokens to the malicious contract's balance
 * 5. **Multiple Rounds**: The attack can continue across multiple re-entrant calls within the same transaction
 * 
 * **Why Multi-Transaction Nature is Required:**
 * - The vulnerability requires the attacker to first deploy a malicious contract (Transaction 1)
 * - The CFO must then call mintToken targeting the malicious contract (Transaction 2)
 * - The malicious contract's onTokenMinted callback enables the reentrancy during Transaction 2
 * - Each re-entrant call within Transaction 2 accumulates state changes
 * - The attack's effectiveness depends on the accumulated state changes across multiple function calls
 * 
 * **State Persistence Aspect:**
 * - balanceOf[target] and totalSupply are permanently modified with each re-entrant call
 * - These state changes persist and compound across multiple re-entrant invocations
 * - The vulnerability exploits the fact that state updates happen before external calls
 * - The accumulated minted tokens remain in the contract's state after the attack
 * 
 * This creates a realistic reentrancy vulnerability that requires careful setup and exploitation across multiple transaction contexts, making it a genuine stateful, multi-transaction security flaw.
 */
pragma solidity ^0.4.24;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store initial state for consistency checks
        uint256 initialBalance = balanceOf[target];
        uint256 initialTotalSupply = totalSupply;
        // Update state before external call (vulnerable pattern)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[target] += amount;
        totalSupply += amount;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call to target before final state validation
        // This allows reentrancy where target can call mintToken again
        if (isContract(target)) {
            target.call(abi.encodeWithSignature("onTokenMinted(uint256)", amount));
            // Continue execution regardless of callback success
        }
        // Emit event after external call (state already modified)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit MintToken (target, amount);
        return true;
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
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