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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Moved Transfer events**: Placed Transfer events before external call to maintain event ordering
 * 2. **Added external call**: Introduced `target.call(bytes4(keccak256("onTokenMinted(uint256)")), initialSupply)` to notify target contract of minting
 * 3. **Moved state updates**: Critically moved `balanceOf[target] += initialSupply` and `totalSupply += initialSupply` AFTER the external call
 * 4. **Added contract detection**: Added `target.code.length > 0` check to only call contracts, making the vulnerability more realistic
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract at address `maliciousContract`
 * - The malicious contract implements `onTokenMinted(uint256)` callback
 * - Attacker calls `mintToken(maliciousContract, 1000)`
 * - During the external call, the malicious contract's `onTokenMinted` function is triggered
 * - Inside the callback, the attacker calls `mintToken(maliciousContract, 1000)` again (reentrancy)
 * - The first call's state updates haven't occurred yet, so `balanceOf[maliciousContract]` is still 0
 * - The reentrant call proceeds normally and updates state first
 * - When the original call resumes, it updates state again, causing double minting
 * 
 * **Transaction 2-N (Exploitation):**
 * - The attacker can repeat this process across multiple transactions
 * - Each transaction exploits the accumulated state corruption from previous calls
 * - The vulnerability compounds as the attacker builds up illegitimate token balances
 * - State corruption persists between transactions, enabling continued exploitation
 * 
 * **Why Multiple Transactions Are Required:**
 * 1. **State Accumulation**: Each reentrancy call builds up additional corrupted state that persists
 * 2. **Compounding Effect**: The vulnerability becomes more profitable with repeated exploitation across transactions
 * 3. **Realistic Detection Evasion**: Single-transaction exploitation would be more easily detected; multi-transaction exploitation mimics normal usage patterns
 * 4. **Persistent State Corruption**: The illegitimate balances persist between transactions, enabling the attacker to transfer or use tokens obtained through previous exploitations
 * 
 * **Exploitation Flow:**
 * ```
 * Transaction 1: mintToken(attacker, 1000)
 *   → External call to attacker contract
 *   → Attacker reenters: mintToken(attacker, 1000)
 *   → Inner call completes: balanceOf[attacker] = 1000, totalSupply = 1000
 *   → Outer call completes: balanceOf[attacker] = 2000, totalSupply = 2000
 *   → Net result: 2000 tokens minted instead of 1000
 * 
 * Transaction 2: mintToken(attacker, 1000)
 *   → Starting with balanceOf[attacker] = 2000
 *   → Reentrancy exploitation occurs again
 *   → Net result: balanceOf[attacker] = 4000, totalSupply = 4000
 * 
 * Transaction 3: attacker transfers tokens or repeats exploitation
 * ```
 * 
 * This creates a stateful, multi-transaction vulnerability where the attacker's accumulated illegitimate balance from previous transactions enables continued exploitation and value extraction.
 */
pragma solidity ^0.4.16;

contract SusanTokenERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 4;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function SusanTokenERC20() public {
        totalSupply = 100000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "SusanToken";
        symbol = "SUTK";
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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }

    // Fixed definition with reentrancy vulnerability intact
    function mintToken(address target, uint256 initialSupply) public{
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        Transfer(0, msg.sender, initialSupply);
        Transfer(msg.sender, target,initialSupply);
        
        // External call to notify target of minting - VULNERABLE TO REENTRANCY
        if(isContract(target)) {
            target.call(bytes4(keccak256("onTokenMinted(uint256)")), initialSupply);
        }
        
        // State updates occur AFTER external call - CRITICAL VULNERABILITY
        balanceOf[target] += initialSupply;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply += initialSupply;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }
}
