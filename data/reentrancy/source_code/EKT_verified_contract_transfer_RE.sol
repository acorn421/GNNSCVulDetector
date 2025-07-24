/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing all state updates. The vulnerability violates the Checks-Effects-Interactions pattern by:
 * 
 * 1. **State Modification Order**: The sender's balance is updated before the external call, but the recipient's balance is updated AFTER the external call, creating an inconsistent state window.
 * 
 * 2. **Multi-Transaction Exploitation**: An attacker can exploit this across multiple transactions:
 *    - Transaction 1: Attacker calls transfer() to malicious contract
 *    - During callback: Malicious contract sees sender's balance reduced but recipient's balance not yet increased
 *    - Callback Transaction: Malicious contract calls transfer() again, seeing the reduced sender balance from previous transaction
 *    - This creates a state accumulation vulnerability where each transaction builds upon the state changes from previous transactions
 * 
 * 3. **Persistent State Vulnerability**: The vulnerability requires state changes that persist between transactions - each call to transfer() modifies the persistent balanceOf mapping, and these changes are visible to subsequent transactions.
 * 
 * 4. **Realistic Integration**: The external call is disguised as a legitimate ERC-777 style recipient notification hook, making it appear as a reasonable feature addition rather than an obvious vulnerability.
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the callback to occur DURING the transfer process, with the ability to make additional transfer calls that can observe and exploit the intermediate state created by previous transactions.
 */
pragma solidity ^0.4.16;

contract EKT {

    string public name = "EDUCare";      //  token name
    string public symbol = "EKT";           //  token symbol
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;

    address owner = 0x0;

    uint256 constant valueTotal = 10 * 10000 * 10000 * 100000000;  //总量 10亿
    uint256 constant valueFounder = valueTotal / 100 * 50;  // 基金会50%
    uint256 constant valueSale = valueTotal / 100 * 15;  // ICO 15%
    uint256 constant valueVip = valueTotal / 100 * 20;  // 私募 20%
    uint256 constant valueTeam = valueTotal / 100 * 15;  // 团队与合作伙伴 15%

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier validAddress(address _address) {
        assert(0x0 != _address);
        _;
    }

    function EKT(address _founder, address _sale, address _vip, address _team)
        public
        validAddress(_founder)
        validAddress(_sale)
        validAddress(_vip)
        validAddress(_team)
    {
        owner = msg.sender;
        totalSupply = valueTotal;

        // 基金会
        balanceOf[_founder] = valueFounder;
        emit Transfer(0x0, _founder, valueFounder);

        // ICO
        balanceOf[_sale] = valueSale;
        emit Transfer(0x0, _sale, valueSale);

        // 私募
        balanceOf[_vip] = valueVip;
        emit Transfer(0x0, _vip, valueVip);

        // 团队
        balanceOf[_team] = valueTeam;
        emit Transfer(0x0, _team, valueTeam);
    }

    function transfer(address _to, uint256 _value)
        public
        validAddress(_to)
        returns (bool success)
    {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update sender's balance first
        balanceOf[msg.sender] -= _value;
        
        // Notify recipient contract if it's a contract (ERC-777 style hook)
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // External call before completing all state updates
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", msg.sender, _value));
            // Continue even if call fails to maintain compatibility
        }
        // Complete the transfer by updating recipient's balance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value)
        public
        validAddress(_from)
        validAddress(_to)
        returns (bool success)
    {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value)
        public
        validAddress(_spender)
        returns (bool success)
    {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
