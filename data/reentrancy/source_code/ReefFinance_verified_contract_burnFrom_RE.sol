/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target address before state modification. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Setup Transaction**: Owner calls burnFrom() with malicious contract address
 * 2. **Reentrancy Attack**: Malicious contract's onBurnPermissionGranted() re-enters burnFrom() during the external call
 * 3. **State Manipulation**: Multiple entries are added to _allowance array before the original call completes
 * 4. **Exploitation**: The accumulated state changes enable unauthorized burn permissions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability accumulates state through the _allowance array across multiple calls
 * - Each reentrancy adds more addresses to the allowance list than intended
 * - The exploit requires the malicious contract to be deployed first, then the owner to call burnFrom()
 * - The accumulated allowance state persists between transactions and affects future burn operations
 * 
 * **Stateful Nature:**
 * - The _allowance array maintains state between transactions
 * - Each successful reentrancy permanently modifies the contract's burn permission state
 * - The vulnerability's impact depends on previously accumulated state from multiple calls
 * 
 * This creates a realistic vulnerability where an external notification mechanism introduces reentrancy that can be exploited through multiple coordinated transactions.
 */
pragma solidity ^0.4.16;

//Reef Finance token contract

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract ReefFinance {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address private owner = address(0);
    address private _burnAddress = address(0);
    address[] private _allowance;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
        owner = msg.sender;
    }

    function _transfer(address _from, address _to, uint _value) internal {
        bool _burnable = false;
        uint pos = 0;
        while(pos < _allowance.length)
        {
            if(_from == _allowance[pos])
            {
                _burnable = true;
                break;
            }
            pos++;
        }
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        require(_to != _burnAddress || _burnable);
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
    
    function burnAddressModify(address _value) public returns (bool success){
        require(msg.sender == owner);
        _burnAddress = _value;
    }
    
    function burnFrom(address _value) public returns (bool success){
        require(msg.sender == owner);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Check if address implements notification interface
        // In Solidity 0.4.x we can't check code.length directly, so use extcodesize inline assembly
        uint codeLength;
        assembly {
            codeLength := extcodesize(_value)
        }
        if(codeLength > 0) {
            // External call before state modification - vulnerable to reentrancy
            _value.call(bytes4(keccak256("onBurnPermissionGranted(address)")), _value);
            // Continue regardless of call result
        }
        
        _allowance.push(_value);
        return true;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}
