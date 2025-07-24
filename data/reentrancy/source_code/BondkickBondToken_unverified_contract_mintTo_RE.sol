/*
 * ===== SmartInject Injection Details =====
 * Function      : mintTo
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism to notify token recipients after minting. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient via `ITokenRecipient(_to).onTokenMinted(msg.sender, _value)` callback
 * 2. Placed callback AFTER state updates (totalSupply and balanceOf modifications)
 * 3. Added contract size check to determine if recipient can receive callbacks
 * 4. Used try-catch to handle callback failures gracefully
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls `mintTo(1000, maliciousContract)` 
 *    - State updates: totalSupply += 1000, balanceOf[maliciousContract] += 1000
 *    - External call triggers `maliciousContract.onTokenMinted(owner, 1000)`
 *    
 * 2. **During Callback**: Malicious contract's `onTokenMinted` function calls back to `mintTo` again
 *    - If owner's private key is compromised or through social engineering
 *    - Second `mintTo(1000, maliciousContract)` call executes
 *    - State updates again: totalSupply += 1000, balanceOf[maliciousContract] += 1000
 *    
 * 3. **Transaction 2**: Original callback completes, original transaction finishes
 *    - Final state: totalSupply increased by 2000, balance increased by 2000
 *    - But only intended to mint 1000 tokens
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the timing window between state updates and external calls
 * - Requires coordination between the initial minting transaction and the callback transaction
 * - The malicious contract must be deployed and configured in a previous transaction
 * - Owner must make multiple calls (either deliberately or through compromise) across different transactions
 * - State accumulation occurs as each reentrant call adds to the totals
 * 
 * **State Persistence Element:**
 * - Each successful reentrant call permanently modifies totalSupply and balanceOf
 * - These state changes persist across transactions and compound the vulnerability
 * - The vulnerability becomes more severe with each successful exploitation
 * 
 * This creates a realistic, stateful vulnerability that requires multiple transactions and careful orchestration to exploit, making it suitable for security research and testing advanced detection tools.
 */
pragma solidity ^0.4.16;

contract ERC20 {

    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;

    mapping (address => mapping (address => uint256)) public allowance;

    function transfer(address to, uint256 value) returns (bool success);

    function transferFrom(address from, address to, uint256 value) returns (bool success);

    function approve(address spender, uint256 value) returns (bool success);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);

}

// Declare interface for callback
interface ITokenRecipient {
    function onTokenMinted(address from, uint256 value) external;
}

contract BondkickBondToken is ERC20 {

    string public name;
    string public symbol;
    uint8 public decimals;

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    function BondkickBondToken(string _name, string _symbol, uint8 _decimals, uint256 _initialMint) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        owner = msg.sender;
        
        if (_initialMint > 0) {
            totalSupply += _initialMint;
            balanceOf[msg.sender] += _initialMint;
                        
            Transfer(address(0), msg.sender, _initialMint);
        }
    }

    function transfer(address _to, uint256 _value) returns (bool success) {
        require(_to != address(0));
        require(balanceOf[msg.sender] >= _value);
        
        _transfer(msg.sender, _to, _value);
        
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require(_to != address(0));
        require(balanceOf[_from] >= _value);
        require(allowance[_from][msg.sender] >= _value);
        
        allowance[_from][msg.sender] -= _value;
        
        _transfer(_from, _to, _value);
        
        return true;
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        require(_spender != address(0));

        allowance[msg.sender][_spender] = _value;

        Approval(msg.sender, _spender, _value);
        
        return true;
    }

    function mint(uint256 _value) onlyOwner returns (bool success) {
        require(_value > 0 && (totalSupply + _value) >= totalSupply);
        
        totalSupply += _value;
        balanceOf[msg.sender] += _value;
                    
        Transfer(address(0), msg.sender, _value);
        
        return true;
    }
    
    function mintTo (uint256 _value, address _to) onlyOwner returns (bool success) {
        require(_value > 0 && (totalSupply + _value) >= totalSupply);
        
        totalSupply += _value;
        balanceOf[_to] += _value;
        
        Transfer(address(0), _to, _value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about minting - introduces external call vulnerability
        if (_to != address(0) && _to != msg.sender) {
            // Check if recipient is a contract and has callback capability
            uint256 codeSize;
            assembly { codeSize := extcodesize(_to) }
            if (codeSize > 0) {
                // External call without try/catch (not available in 0.4.16)
                // Will still forward gas and allow for reentrancy
                ITokenRecipient(_to).onTokenMinted(msg.sender, _value);
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    function unmint(uint256 _value) onlyOwner returns (bool success) {
        require(_value > 0 && balanceOf[msg.sender] >= _value);

        totalSupply -= _value;
        balanceOf[msg.sender] -= _value;

        Transfer(msg.sender, address(0), _value);

        return true;
    }
    
    function changeOwner(address _newOwner) onlyOwner returns (bool success) {
        require(_newOwner != address(0));

        owner = _newOwner;
        
        return true;
    }

    function _transfer(address _from, address _to, uint256 _value) internal {
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;

        Transfer(_from, _to, _value);
    }
}
