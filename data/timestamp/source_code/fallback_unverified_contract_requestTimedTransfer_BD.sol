/*
 * ===== SmartInject Injection Details =====
 * Function      : requestTimedTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence issue. The vulnerability occurs because: 1) Users can request timed transfers that lock tokens until a specific timestamp, 2) The executeTimedTransfer function relies on 'now' (block.timestamp) for time checks, which can be manipulated by miners within certain bounds, 3) The vulnerability is stateful as it requires multiple transactions: first requestTimedTransfer to set up the state, then executeTimedTransfer to exploit the timestamp manipulation, 4) Miners can potentially delay or accelerate the execution of timed transfers by manipulating block timestamps, affecting the release timing of locked tokens.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These variables and functions are moved to the contract scope
    mapping (address => uint256) public timedTransferRequests;
    mapping (address => uint256) public timedTransferAmounts;
    mapping (address => address) public timedTransferTargets;

    function requestTimedTransfer(address _to, uint256 _value, uint256 _releaseTime) 
        public 
        validAddress(_to) 
        returns (bool success) 
    {
        require(balanceOf[msg.sender] >= _value);
        require(_releaseTime > now);
        
        timedTransferRequests[msg.sender] = _releaseTime;
        timedTransferAmounts[msg.sender] = _value;
        timedTransferTargets[msg.sender] = _to;
        
        // Lock the tokens by reducing balance
        balanceOf[msg.sender] -= _value;
        
        return true;
    }

    function executeTimedTransfer() 
        public 
        returns (bool success) 
    {
        require(timedTransferRequests[msg.sender] > 0);
        require(now >= timedTransferRequests[msg.sender]);
        
        address target = timedTransferTargets[msg.sender];
        uint256 amount = timedTransferAmounts[msg.sender];
        
        // Transfer tokens to target
        balanceOf[target] += amount;
        
        // Clear the request
        timedTransferRequests[msg.sender] = 0;
        timedTransferAmounts[msg.sender] = 0;
        timedTransferTargets[msg.sender] = 0x0;
        
        Transfer(msg.sender, target, amount);
        return true;
    }

    function cancelTimedTransfer() 
        public 
        returns (bool success) 
    {
        require(timedTransferRequests[msg.sender] > 0);
        
        uint256 amount = timedTransferAmounts[msg.sender];
        
        // Return tokens to sender
        balanceOf[msg.sender] += amount;
        
        // Clear the request
        timedTransferRequests[msg.sender] = 0;
        timedTransferAmounts[msg.sender] = 0;
        timedTransferTargets[msg.sender] = 0x0;
        
        return true;
    }
    // === END FALLBACK INJECTION ===

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
        Transfer(0x0, _founder, valueFounder);

        // ICO
        balanceOf[_sale] = valueSale;
        Transfer(0x0, _sale, valueSale);

        // 私募
        balanceOf[_vip] = valueVip;
        Transfer(0x0, _vip, valueVip);

        // 团队
        balanceOf[_team] = valueTeam;
        Transfer(0x0, _team, valueTeam);

    }

    function transfer(address _to, uint256 _value)
        public
        validAddress(_to)
        returns (bool success)
    {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
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
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value)
        public
        validAddress(_spender)
        returns (bool success)
    {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }


    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
