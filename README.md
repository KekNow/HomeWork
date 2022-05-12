# Запуск
Запуск производился на `python 3.8`

Программа использует следующие библиотеки: `time` для замера времени, `bitarray` для оптимизации взаимодействия с битовыми операциями и несколько функций из `heapq` для использования кучи

Чтобы запустить программу, введите в терминале `python main.py` и следуйте следующим инструкциям:

Выберите режим `Enter the mode (c/compress/z/zip or d/decompress/u/unzip or t/test)`

При компрессии: введите имя файла который хотите сжать  
`Enter the name of the file you want to compress:`

При декомпрессии: введите файл с расширением .zmh и исходное расширение  
`Enter the name of the file you want to decompress (need to .zmh extension)`  
`Enter the extension of the file you want to decompress (like .jpeg)`

Режим test по введённому названию файла прогоняет весь пайплайн: сжимает файл, затем разжимает и сравнивает его с оригинальным - всё ли прошло успешно или нет

# Пояснительная записка

## Проблема с заполненностью последнего байта

Проблема с заполненностью последнего байта была решена добавлением 3 битов в самое начало файла - они сохраняют информацию о количестве недостающих бит в последнем байте до полного. Поскольку такое число может лежать в пределах от 0 до 7, 3 бит на эту информацию вполне достаточно. При сжатии последний байт дополняется нулями, а количество добавленных нулей переводится в двоичное число и добавляется в эти 3 первых бита сжатого файла. При разархивации файла первым делом извлекается эта информация и отсекаются все лишние нули: извлекается первые 3 бита, преобразуется в int - полученное число бит отсекается с конца файла.

## Проблема с сохранением словаря

После этих 3 бит лежит 1 байт с количеством видов различных байт в оригинальном файле - этот байт записывается в переменную len_dict, которая используется при разархивации. Если число было равно 256, этот байт заполняется нулями.

Словарь вида {188: bitarray('00'), 139: bitarray('0100'), ...} переводится по следующим правилам: для каждой пары ключ-значение, ключ заносится в отдельный байт, затем в следующий байт заносится число бит, которое занимает значение по этому ключу (для bitarray('00') - 2, для bitarray('0100') - 4 и т.д.), после чего считывается ровно то количество бит, что было указано в этом втором байте. Считанные биты и являются шифр-кодом, а данная итерация проводится по в цикле for i in range(len_dict).

## Результаты тестирования

В основном картинки, поскольку в них довольно равномерно встречаются все биты и нельзя выделить наиболее частые или редкие биты, сжимаются плохо. Также это происходит потому, что многие форматы уже ориентированы на занятие как можно меньшего размера (например JPEG или MP4). Аналогичная ситуация с pdf-файлами и подобным образом "сжимаются" аудиофайлы и видеофайлы.
Тем не менее текст программы в Jupiter notebook сжимается в ~5 раз, как и многие другие текстовые файлы. В целом архиватор показывает хороший результат для файлов с неравномерным распределением частоты встречаемости байт.

Сжатие происходит довольно быстро, однако извлечение занимает в несколько раз больше времени, поскольку недетерминирована длина шифр-кода для каждого байта. Тем не менее сжимается файл размером 65 Мб за 10 секунд, а извлекается за 81 секунду, что является не очень плохим результатом.

## Сравнение с другими архиваторами

Очевидно, масштабируемость данного архиватора в сравнении с другими очень плохая - при увеличении количества байт в исходном файле разархивация будет происходить значительно медленее, в то время как архиваторы zip, 7z и другие не так сильно увеличивают своё время работы в зависимости от величины архивируемого файла. Тем не менее скорость архивации сопоставима и zmh не так сильно отстаёт от собратьев. Среди недостатков zmh можно также перечислить довольно большой словарь для файлов, где встречаются большинство видов байт - это сильно урезает размер сжатия, даже несмотря на его довольно скрупулёзную реализацию в моей программе. Также сжатия практически не происходит для файлов, в которых равномерно распределены все байты (все имеют примерно одинаковую частоту встречаемости), что сильно сужает область применимости данного архиватора до текстовых файлов, в которых он уже очень успешно работает и показывает превосходные результаты.
