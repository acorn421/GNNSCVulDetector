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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder (_from) before state updates. This creates a callback mechanism that allows the _from address to re-enter the contract during the burn process, exploiting the inconsistent state window where checks have passed but state updates haven't occurred yet.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Transaction 1 - Setup Phase:**
 *    - Attacker deploys a malicious contract and obtains tokens
 *    - Attacker approves a spender to burn tokens on their behalf
 *    - Sets up initial state with sufficient balance and allowance
 * 
 * 2. **Transaction 2 - Exploitation Phase:**
 *    - Spender calls burnFrom() on the malicious contract address
 *    - During the external call to onTokenBurn(), the malicious contract can:
 *      - Re-enter burnFrom() with the same parameters
 *      - Exploit the fact that balanceOf and allowance haven't been updated yet
 *      - Burn more tokens than actually owned by manipulating the state inconsistency
 * 
 * 3. **State Persistence Requirement:**
 *    - The vulnerability requires that balanceOf[_from] and allowance[_from][msg.sender] values persist between transactions
 *    - Multiple calls can accumulate exploitation by repeatedly calling burnFrom during reentrancy
 *    - Each reentrant call sees the same pre-burn state values, allowing over-burning
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first set up allowances and balances in separate transactions
 * - The actual exploitation happens when burnFrom is called, triggering the callback
 * - During the callback, the attacker can make additional calls that see inconsistent state
 * - The vulnerability compounds across multiple reentrant calls within the same transaction tree
 * - State changes from previous transactions (allowance setup) enable the current transaction's exploitation
 * 
 * **Realistic Business Logic:**
 * The external call simulates a common pattern where token contracts notify holders about burns, making this a realistic vulnerability that could appear in production code while maintaining the original function's intended behavior.
 */
pragma solidity ^0.4.16;

contract KaiserExToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function KaiserExToken() public {
        totalSupply = 60000000 * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = "KaiserEx Token";
        symbol = "KET";
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
        // Notify the token holder before burning (vulnerable external call)
        if (isContract(_from)) {
            // External call before state updates - creates reentrancy opportunity
            _from.call(abi.encodeWithSignature("onTokenBurn(address,uint256)", msg.sender, _value));
            // Continue even if notification fails
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         
        allowance[_from][msg.sender] -= _value;             
        totalSupply -= _value;                              
        emit Burn(_from, _value);
        return true;
    }

    // Helper for contract code detection in pre-0.8.0 Solidity
    function isContract(address _addr) private view returns (bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}