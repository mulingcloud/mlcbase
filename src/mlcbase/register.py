from typing import Optional, Type


class Registry(dict):
    def __init__(self, name, *args, **kwargs):
        super(Registry, self).__init__(*args, **kwargs)
        self._name = name
        self._dict = dict()
        
    def _register_module(self, 
                         module: Type, 
                         module_name: Optional[str] = None, 
                         force: bool = False):
        if not callable(module):
            raise TypeError(f'module must be Callable, but got {type(module)}')
        
        if module_name is None:
            module_name = module.__name__
        if not force and module_name in self._dict:
            existed_module = self._dict[module_name]
            raise KeyError(f'{module_name} is already registered in {self._name} '
                            f'at {existed_module.__module__}')
        self._dict[module_name] = module
        
    def register_module(self, 
                        name: Optional[str] = None, 
                        module: Optional[Type] = None,
                        force: bool = False):
        if not isinstance(force, bool):
            raise TypeError(f'force must be a boolean, but got {type(force)}')

        # raise the error ahead of time
        if not (name is None or isinstance(name, str)):
            raise TypeError(f'name must be None, an instance of str, but got {type(name)}')

        # use it as a normal method: x.register_module(module=SomeClass)
        if module is not None:
            self._register_module(module=module, module_name=name, force=force)
            return module

        # use it as a decorator: @x.register_module()
        def _register(module):
            self._register_module(module=module, module_name=name, force=force)
            return module

        return _register

    def __call__(self, target):
        return self.register(target)
    
    def __setitem__(self, key, value):
        self._dict[key] = value

    def __getitem__(self, key):
        return self._dict[key]
    
    def __delitem__(self, key):
        del self._dict[key]

    def __iter__(self):
        return iter(self._dict)

    def __len__(self):
        return len(self._dict)

    def __contains__(self, key):
        return key in self._dict
    
    def __str__(self):
        return str(self._dict)
    
    @property
    def name(self):
        return self._name
    
    def keys(self):
        return self._dict.keys()
    
    def values(self):
        return self._dict.values()
    
    def items(self):
        return self._dict.items()
    
    def build(self, cfg: dict):
        if cfg is not None:
            assert isinstance(cfg, dict)
            cfg_ = cfg.copy()
            func_name = cfg_.pop('type')
            return self._dict[func_name](**cfg_)
        else:
            return None


DATABASE = Registry("Database")
EMAIL = Registry("Email Server")
SECRET = Registry("Secret")
FILEOPT = Registry("File Operations")
IMAGEIO = Registry("Image IO")
REMOTE = Registry("Remote Connection")
