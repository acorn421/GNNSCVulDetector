/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a reentrancy vulnerability by adding an external call to the recipient contract after balance updates but before allowance decrement. This creates a stateful, multi-transaction vulnerability where:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `_to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value))` after balance updates
 * 2. Added code length check to only call contracts (not EOAs) to make it more realistic  
 * 3. Placed the external call strategically AFTER balance updates but BEFORE allowance decrement
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * Transaction 1: Attacker sets up malicious contract as _to address with high allowance
 * Transaction 2: Calls transferFrom which triggers the external call to malicious contract
 * Transaction 3: Malicious contract's onTokenReceived function calls transferFrom again (reentrancy)
 * Transaction 4: Second transferFrom call sees updated balances but unchanged allowance, allowing double-spending
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability exploits the state inconsistency between balance updates and allowance decrements
 * - Each reentrant call creates a new transaction context where the allowance hasn't been decremented yet
 * - The attacker needs to accumulate multiple transfers before the allowance is properly decremented
 * - The exploit requires setting up the malicious contract and allowance in separate transactions first
 * 
 * **State Persistence Exploitation:**
 * - balanceOf state persists between transactions, enabling balance manipulation
 * - allowance state remains unchanged during reentrancy, allowing repeated exploitation
 * - The vulnerability accumulates effect across multiple calls, not exploitable in single transaction
 * 
 * This vulnerability is realistic as it mimics ERC777 token receiver hooks and is only exploitable through carefully orchestrated multi-transaction sequences.
 */
pragma solidity ^0.4.11;

contract SwiftDex {

    string public name = "SwiftDex";      //  token name
    string public symbol = "SWIFD";           //  token symbol
    uint256 public decimals = 18;            //  token digit
    uint256 public price = 360000000000000;
    string public version="test-5.0";
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    //000000000000000000
    bool public stopped = false;
    uint256 constant decimalFactor = 1000000000000000000;

    address owner = 0x0;
    address address_ico = 0x82844C2365667561Ccbd0ceBE0043C494fE54D16;
    address address_team = 0xdB96e4AA6c08C0c8730E1497308608195Fa77B31;
    address address_extra = 0x14Eb4D0125769aC89F60A8aA52e114fAe70217Be;
    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    // Changed to constructor
    function SwiftDex () public {
        owner = msg.sender;
        totalSupply = 200000000000000000000000000;

        balanceOf[address_ico] = totalSupply * 70 / 100;
        emit Transfer(0x0, address_ico, totalSupply * 70 / 100);

        balanceOf[address_team] = totalSupply * 15 / 100;
        emit Transfer(0x0, address_team, totalSupply * 15 / 100);

        balanceOf[address_extra] = totalSupply * 15 / 100;
        emit Transfer(0x0, address_extra, totalSupply * 15 / 100);
    }

    function transfer(address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about incoming transfer - VULNERABILITY: External call before allowance update
        if (_isContract(_to)) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function buy() public isRunning payable returns (uint amount){
        amount = msg.value * decimalFactor / price;                    // calculates the amount
        require(balanceOf[address_ico] >= amount);               // checks if it has enough to sell
        balanceOf[msg.sender] += amount;                  // adds the amount to buyer's balance
        balanceOf[address_ico] -= amount;                        // subtracts amount from seller's balance
        address_ico.transfer(msg.value);
        emit Transfer(address_ico, msg.sender, amount);               // execute an event reflecting the change
        return amount;                                    // ends function and returns
    }

    function deployTokens(address[] _recipient, uint256[] _values) public isOwner {
        for(uint i = 0; i< _recipient.length; i++)
        {
              balanceOf[_recipient[i]] += _values[i] * decimalFactor;
              balanceOf[address_ico] -= _values[i] * decimalFactor;
              emit Transfer(address_ico, _recipient[i], _values[i] * decimalFactor);
        }
    }

    function stop() public isOwner {
        stopped = true;
    }

    function start() public isOwner {
        stopped = false;
    }

    function setPrice(uint256 _price) public isOwner {
        price = _price;
    }

    // Helper function to detect contract
    function _isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
